package dnsutil

import (
	"fmt"

	"github.com/miekg/dns"
)

// CompactMsgString generates a relatively compact single-line, printable representation of most of
// the useful data for DoH in dns.Msg. The output is intended to be well suited to printing to a log
// or trace file.
//
// The generated format is: ID/Op/rcode (bits) IN/type/qname ACount/NCount/ECount Answers Auths Extras
func CompactMsgString(m *dns.Msg) string {
	bits := ""
	if m.MsgHdr.Response {
		bits += "R"
	}
	if m.MsgHdr.Authoritative {
		bits += "A"
	}
	if m.MsgHdr.Truncated {
		bits += "T"
	}
	if m.MsgHdr.RecursionDesired {
		bits += "d"
	}
	if m.MsgHdr.RecursionAvailable {
		bits += "a"
	}
	if m.MsgHdr.Zero {
		bits += "Z"
	}
	if m.MsgHdr.AuthenticatedData {
		bits += "s"
	}
	if m.MsgHdr.CheckingDisabled {
		bits += "x"
	}

	qClass := "?"
	qType := "?"
	qName := "?"
	if len(m.Question) > 0 {
		q := m.Question[0]
		qClass = dns.ClassToString[q.Qclass]
		qType = dns.TypeToString[q.Qtype]
		qName = q.Name
	}
	opCode := "?"
	ok := false
	if opCode, ok = dns.OpcodeToString[m.MsgHdr.Opcode]; ok && len(opCode) >= 2 {
		opCode = opCode[0:2]
	}
	s := fmt.Sprintf("%d/%s/%d (%s) %s/%s/%s %d/%d/%d",
		m.MsgHdr.Id, opCode, m.MsgHdr.Rcode, bits,
		qClass, qType, qName, len(m.Answer), len(m.Ns), len(m.Extra))
	s += " A:" + CompactRRsString(m.Answer) + " N:" + CompactRRsString(m.Ns) + " E:" + CompactRRsString(m.Extra)

	return s
}

// CompactRRsString generates a compact String() representation of an array of dns.RRs
func CompactRRsString(rrs []dns.RR) string {
	s := ""
	sep := ""
	for _, interfaceRR := range rrs {
		s += sep
		sep = "/"
		switch rr := interfaceRR.(type) {
		case *dns.A:
			s += "A*" + rr.A.String()
		case *dns.AAAA:
			s += "AAAA*" + rr.AAAA.String()
		case *dns.MX:
			s += fmt.Sprintf("MX*%d-%s", rr.Preference, rr.Mx)
		case *dns.NS:
			s += "NS*" + rr.Ns
		case *dns.SRV:
			s += fmt.Sprintf("SRV*%d-%d-%s:%d", rr.Priority, rr.Weight, rr.Target, rr.Port)
		case *dns.OPT:
			s += fmt.Sprintf("OPT(%d,%d,%d:", rr.Version(), rr.ExtendedRcode(), rr.UDPSize())
			subsep := ""
			for _, option := range rr.Option {
				s += subsep
				subsep = ","
				switch subOpt := option.(type) {
				case *dns.EDNS0_NSID:
					s += "NSID"
				case *dns.EDNS0_SUBNET:
					s += fmt.Sprintf("ECS[%d/%d]", subOpt.SourceNetmask, subOpt.SourceScope)
				case *dns.EDNS0_COOKIE:
					s += "COOKIE"
				case *dns.EDNS0_UL:
					s += "UL"
				case *dns.EDNS0_LLQ:
					s += "LLQ"
				case *dns.EDNS0_DAU:
					s += "DAU"
				case *dns.EDNS0_DHU:
					s += "DHU"
				case *dns.EDNS0_LOCAL:
					s += "LOCAL"
				case *dns.EDNS0_PADDING:
					s += "PAD"
				default:
					s += fmt.Sprintf("%d", option.Option())
				}
			}
			s += ")"
		default:
			s += dns.TypeToString[interfaceRR.Header().Rrtype]
		}
	}

	return s
}
