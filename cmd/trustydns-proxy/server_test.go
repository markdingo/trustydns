package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/markdingo/trustydns/internal/resolver"

	"github.com/miekg/dns"
)

// mockResolver replaces the resolvers used by the server to resolve queries. It simply returns the
// struct values as the "result" of the Resolve() call.
type mockResolver struct {
	ib       bool
	response dns.Msg
	rMeta    resolver.ResponseMetaData
	err      error
}

func (t *mockResolver) InBailiwick(qname string) bool {
	return t.ib
}

func (t *mockResolver) Resolve(query *dns.Msg, qMeta *resolver.QueryMetaData) (*dns.Msg, *resolver.ResponseMetaData, error) {
	return &t.response, &t.rMeta, t.err
}

// mockResponseWriter replaces the dns.ResponseWriter to emulate a real DNS client presenting a
// request and accepting a response.
type mockResponseWriter struct {
	localAddr      net.IPAddr
	remoteAddr     net.IPAddr
	writeMsgError  error
	writeN         int
	writeError     error
	closeError     error
	tsigError      error
	messageWritten *dns.Msg
	bytesWritten   []byte
}

func (t *mockResponseWriter) LocalAddr() net.Addr {
	return &t.localAddr
}

func (t *mockResponseWriter) RemoteAddr() net.Addr {
	return &t.remoteAddr
}
func (t *mockResponseWriter) WriteMsg(m *dns.Msg) error {
	t.messageWritten = m
	return t.writeMsgError
}
func (t *mockResponseWriter) Write(b []byte) (int, error) {
	t.bytesWritten = append(t.bytesWritten, b...)
	return t.writeN, t.writeError
}
func (t *mockResponseWriter) Close() error {
	return t.closeError
}
func (t *mockResponseWriter) TsigStatus() error {
	return t.tsigError
}
func (t *mockResponseWriter) TsigTimersOnly(bool) {
}
func (t *mockResponseWriter) Hijack() {
}

// Test that the actual server starts up when given the simplest of settings.
func TestServerStart(t *testing.T) {
	s := &server{listenAddress: "127.0.0.1:59053", transport: "udp"}
	errorChannel := make(chan error)
	wg := &sync.WaitGroup{} // Wait on all servers
	s.start(errorChannel, wg)
	var err error
	defer s.stop()
	select {
	case e := <-errorChannel:
		err = e
	case <-time.After(time.Millisecond * 100): // Give it time to start up or fail
	}
	if err != nil {
		t.Error(err)
	}
}

// Test basic resolve flow thru the server
func TestServerBasicQuery(t *testing.T) {
	mainInit(os.Stdout, os.Stderr)
	resolver := &mockResolver{ib: true} // Returns true on call to InBailiwick()
	resolver.response.MsgHdr.Id = 4001
	s := &server{local: resolver}
	mw := &mockResponseWriter{}
	q := &dns.Msg{}
	q.SetQuestion("example.com.", dns.TypeNS)
	q.Id = 23
	s.ServeDNS(mw, q) // Should have written to mockResponseWriter.WriteMsg()
	if mw.messageWritten == nil {
		t.Error("ServeDNS did not get to the point of writing a response message")
	}
	if mw.messageWritten.MsgHdr.Id != 4001 { // Got a message, was it the reply from the resolver?
		t.Error("ServeDNS did not write the resolver response back to the client, got:", mw.messageWritten)
	}

	// Check that all of the basic stats counters and bools were set

	if s.cct.Peak(false) != 1 {
		t.Error("ServeDNS did not bump concurrency counter to 1", s.cct.Peak(false))
	}
	if s.successCount != 1 {
		t.Error("ServeDNS did not call addSuccessStats() at completion of function", s.stats)
	}
}

// Test that normal logging branches are taken
func TestServerLogging(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	mainInit(stdout, stderr)
	cfg.logClientIn = true
	cfg.logClientOut = true
	resolver := &mockResolver{ib: true}
	s := &server{local: resolver}
	mw := &mockResponseWriter{}
	q := &dns.Msg{}
	q.SetQuestion("example.com.", dns.TypeNS)
	s.ServeDNS(mw, q) // Generates Normal logging In and Out
	outStr := stdout.String()
	if !strings.Contains(outStr, "Cl:") {
		t.Error("Logging did not log Client In Message")
	}
	if !strings.Contains(outStr, "CO:") {
		t.Error("Logging did not log Client Out Message")
	}
}

// Test for error return from the resolver. Check error logging while we're at it.
func TestServerResolverError(t *testing.T) {
	stdout := &bytes.Buffer{}
	mainInit(stdout, os.Stderr)
	cfg.logClientOut = true
	resolver := &mockResolver{err: errors.New("Mock Resolver Error")} // Resolver returns an err
	s := &server{remote: resolver}
	mw := &mockResponseWriter{}
	q := &dns.Msg{}
	q.SetQuestion("example.com.", dns.TypeNS)

	s.ServeDNS(mw, q)
	if s.failureCounters[serNoResponse] != 1 { // This gets set with error return from Resolve()
		t.Error("ServeDNS did not notice error return from Resolv(). Stats:", s.stats)
	}
	if mw.messageWritten != nil { // Belts and braces check rather than just a counter check
		t.Error("Ho boy. ServeDNS really ignored resolve errors and wrote a mystery response")
	}

	// Error path is working. Let's see if the logging part of it worked
	outStr := stdout.String()
	if !strings.Contains(outStr, "Mock Resolver Error") {
		t.Error("Expected Mock Resolver Error due to mock error, not", outStr)
	}
}

// Test for error return from dbs.WriteMsg. Check for error logging while we're at it.
func TestServerWriteMsgError(t *testing.T) {
	stdout := &bytes.Buffer{}
	mainInit(stdout, os.Stderr)
	cfg.logClientOut = true
	resolver := &mockResolver{}
	s := &server{remote: resolver}
	mw := &mockResponseWriter{writeMsgError: errors.New("Mock writeMsgError")}
	q := &dns.Msg{}
	q.SetQuestion("example.com.", dns.TypeNS)

	s.ServeDNS(mw, q)
	if s.failureCounters[serDNSWriteFailed] != 1 { // This gets set with error return from WriteMsg()
		t.Error("ServeDNS did not notice error return from Resolv(). Stats:", s.stats)
	}

	// Error path looks ok. Did the error get logged?
	outStr := stdout.String()
	if !strings.Contains(outStr, "Mock writeMsgError") {
		t.Error("Expected Mock writeMsgError due to mock error, not", outStr)
	}

}

func TestServerTruncation(t *testing.T) {
	mainInit(os.Stdout, os.Stderr)
	resolver := &mockResolver{ib: true}
	response := dns.Msg{} // Keep a copy as truncation modifies response in-situ
	response.MsgHdr.Id = 5001
	a1, _ := dns.NewRR("example.com. IN TXT \"100 bytes of aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"")
	for response.Len() <= 1024 {
		response.Answer = append(response.Answer, a1)
	}
	resolver.response = response
	resolver.rMeta.PayloadSize = resolver.response.Len() // This is what server looks at for msg length

	// Test for no truncate case as transport is TCP
	s := &server{remote: resolver, transport: "tcp"} // Should *NOT* truncate as transport is TCP
	mw := &mockResponseWriter{}
	q := &dns.Msg{}
	q.SetQuestion("example.com.", dns.TypeNS)

	s.ServeDNS(mw, q)
	if mw.messageWritten == nil {
		t.Fatal("Test setup failed as response never got written to mockResponseWriter")
	}
	if mw.messageWritten.MsgHdr.Truncated {
		t.Error("Message truncated when returned to a TCP client - oops")
	}
	if mw.messageWritten.Len() <= 512 {
		t.Error("Message silently truncated", mw.messageWritten)
	}

	// Test for truncate when msg exceeds system default size of 512 and we're udp
	s.transport = "udp"
	resolver.response = response // Refresh response
	resolver.rMeta.PayloadSize = resolver.response.Len()
	mw.messageWritten = nil
	s.ServeDNS(mw, q)
	if mw.messageWritten == nil {
		t.Fatal("Test setup failed as response never got written to mockResponseWriter")
	}
	if !mw.messageWritten.MsgHdr.Truncated {
		t.Error("Message was not truncated when it should have been")
	}
	if mw.messageWritten.Len() > 512 {
		t.Error("Message not truncated down to system limit", mw.messageWritten.Len())
	}
	if len(mw.messageWritten.Answer) == len(response.Answer) {
		t.Error("Answer Count wasn't reduced with truncate. Still at", len(response.Answer))
	}

	// Test for edns0 protection of message GT system default size
	resolver.response = response // Refresh response
	resolver.rMeta.PayloadSize = resolver.response.Len()

	o := &dns.OPT{ // Add edns0 limit to the query not the response
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	o.SetUDPSize(uint16(resolver.response.Len() + 1))
	q.Extra = append(q.Extra, o) // Server checks query for edns, not the response

	mw.messageWritten = nil
	s.ServeDNS(mw, q)
	if mw.messageWritten == nil {
		t.Fatal("Test setup failed as response never got written to mockResponseWriter")
	}
	if mw.messageWritten.MsgHdr.Truncated {
		t.Error("Message truncated when it should have been protected by edns0", mw.messageWritten.Len())
	}
	if mw.messageWritten.Len() != response.Len() {
		t.Error("Message size changed with no TC=1. Got:", mw.messageWritten.Len(), "was:", response.Len())
	}

	// Test for truncate to edns0 limit
	resolver.response = response // Refresh response
	resolver.rMeta.PayloadSize = resolver.response.Len()

	o.SetUDPSize(768) // GT system, less than message len of 1024++
	q.Extra = append(q.Extra, o)

	mw.messageWritten = nil
	s.ServeDNS(mw, q)
	if mw.messageWritten == nil {
		t.Fatal("Test setup failed as response never got written to mockResponseWriter")
	}
	if !mw.messageWritten.MsgHdr.Truncated {
		t.Error("Message should have Truncated set", mw.messageWritten.Len())
	}
	if mw.messageWritten.Len() < 600 { // Did truncate notice the EDNS setting or use system default?
		t.Error("Truncate ignored edns override of system limit. Reduced to", mw.messageWritten.Len())
	}

	if mw.messageWritten.Len() > 768 {
		t.Error("Truncate ignored edns override of system limit. Reduced to", mw.messageWritten.Len())
	}
}
