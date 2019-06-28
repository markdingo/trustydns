/*
Package dnsutil provides helper methods to manipulate the fiddly EDNS0 Client Subnet bits, TTL
reduction and RFC8467 padding in a "github.com/miekg/dns.Msg". The caller is assumed to have
checked that the dns.Msg is a legitimate IN/Query prior to calling any of these functions.
*/
package dnsutil

import (
	"net"

	"github.com/markdingo/trustydns/internal/constants"

	"github.com/miekg/dns"
)

var (
	consts = constants.Get()
)

// FindOPT searches dns.Msg.Extra for the first occurrence of an OPT RR. There should only be one.
//
// Return *dns.OPT if found otherwise nil
func FindOPT(q *dns.Msg) *dns.OPT {
	for _, rr := range q.Extra { // Search Extra for OPT RRs
		if opt, ok := rr.(*dns.OPT); ok {
			return opt
		}
	}

	return nil
}

// FindECS searches dns.Msg.Extra for any occurrences of an EDNS_SUBNET sub-option in any
// occurrences of a dns.OPT in the Extra list of RRs. This multi-occurrence search is more
// aggressive than the standard DNS Message format intends but we really don't want an ECS to be
// missed even if it is ostensibly not in exactly the right place.
//
// If an EDNS_SUBNET sub-option is found, return the containing OPT RR and sub-option otherwise
// return nil, nil
func FindECS(q *dns.Msg) (*dns.OPT, *dns.EDNS0_SUBNET) {
	for _, rr := range q.Extra { // Search Extra for OPT RRs
		if opt, ok := rr.(*dns.OPT); ok {
			for _, subOpt := range opt.Option { // Search OPT RR for ECS
				if ecs, ok := subOpt.(*dns.EDNS0_SUBNET); ok {
					return opt, ecs
				}
			}
		}
	}

	return nil, nil
}

// RemoveEDNS0FromOPT aggressively removes all occurrences of the specified EDNS0 sub-option in the
// Extra RR list of a dns.Msg. It makes the worst-case assumption that there may be multiple options
// and sub-options.
//
// True is returned if at least one sub-option was removed.
func RemoveEDNS0FromOPT(msg *dns.Msg, edns0Code uint16) (removed bool) {
	outRRs := make([]dns.RR, 0) // Construct an array of surviving RRs
	for _, rr := range msg.Extra {
		inOpt, ok := rr.(*dns.OPT)
		if !ok { // Non OPT RRs get copied straight across
			outRRs = append(outRRs, rr)
			continue
		}

		outOpt := &dns.OPT{Hdr: inOpt.Hdr} // Create a new OPT RR to contain the option survivors
		for _, opt := range inOpt.Option { // Search within the OPT RR for the ECS option
			if opt.Option() == edns0Code {
				removed = true
				continue
			}
			outOpt.Option = append(outOpt.Option, opt) // Non-ECS options survive
		}
		if len(outOpt.Option) > 0 { // Only append new OPT RR if it's not empty
			outRRs = append(outRRs, outOpt)
		}
	}

	if removed {
		msg.Extra = outRRs // Return survivors to the message - if any
	}

	return
}

// CreateECS arbitrarily creates an EDNS0_SUBNET sub-option which is appended to the OPT in the
// Extra section of the dns.Msg. If no OPT exists, one is created. This function does not check for
// any pre-existing EDNS0_SUBNET sub-option.
//
// Return the created ecs option.
func CreateECS(msg *dns.Msg, family, prefixLength int, ip net.IP) *dns.EDNS0_SUBNET {
	ecs := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        uint16(family),
		SourceNetmask: uint8(prefixLength),
		Address:       ip, // dns.OPT.pack() truncate this to SourceNetmask
	}

	optRR := FindOPT(msg)
	if optRR == nil { // if necessary, construct an OPT RR to contain the new ECS sub-opt
		optRR = NewOPT()
		msg.Extra = append(msg.Extra, optRR)
	}

	optRR.Option = append(optRR.Option, ecs)

	return ecs
}

// ReduceTTL reduces the TTL in all the RRs in Answer, Ns and Extra that have a TTL greater than 1.
// "by" defines how much to reduce TTLs by and "minimum" is the lower limit that we'll ever let a
// TTL reduce to.
func ReduceTTL(msg *dns.Msg, by uint32, minimum uint32) int {
	changeCount := 0
	if len(msg.Answer) > 0 {
		changeCount += reduceRRSet(msg.Answer, int64(by), int64(minimum))
	}
	if len(msg.Ns) > 0 {
		changeCount += reduceRRSet(msg.Ns, int64(by), int64(minimum))
	}
	if len(msg.Extra) > 0 {
		changeCount += reduceRRSet(msg.Extra, int64(by), int64(minimum))
	}

	return changeCount
}

// Helper that does the actual TTL Reduction work for the supplied RRSet. Even tho the "by" and
// "minimum" are int64 parameters we know that they originated from a uint32 so calcs in 64bit
// comfortably fit the full range of possible values without contortions.
func reduceRRSet(rrset []dns.RR, by int64, minimum int64) int {
	changeCount := 0
	for _, rr := range rrset {
		hdr := rr.Header()
		ttl := int64(hdr.Ttl) // Do all calcs in 64bit signed to capture interim negatives
		if ttl > minimum {    // Cannot reduce a ttl if it's already at the minimum
			ttl -= by          // Could go negative here
			if ttl < minimum { // but this catches negatives as well as too small
				ttl = minimum
			}
			if uint32(ttl) != hdr.Ttl { // Only return if we actually changed the value
				hdr.Ttl = uint32(ttl)
				changeCount++
			}
		}
	}

	return changeCount
}

// NewOPT creates a populated msg.OPT RR as a zero-values struct is not a valid OPT. Note that
// SetUDPSize has to be set for some resolvers that are ECS aware. In particular unbound does not
// seem to like a UDP size of zero.
func NewOPT() *dns.OPT {
	optRR := &dns.OPT{}
	optRR.SetVersion(0)
	optRR.SetUDPSize(dns.DefaultMsgSize)
	optRR.Hdr.Name = "."
	optRR.Hdr.Rrtype = dns.TypeOPT

	return optRR
}
