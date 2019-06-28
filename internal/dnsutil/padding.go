package dnsutil

import (
	"fmt"

	"github.com/miekg/dns"
)

// FindPadding searches dns.Msg.Extra for any occurrences of an EDNS0_PADDING sub-option in any
// occurrences of a dns.OPT in the Extra list of RRs. The presence of padding is a signal from a DoH
// client to a DoH server to pad the response.
//
// Return length of padding else -1
func FindPadding(q *dns.Msg) int {
	for _, rr := range q.Extra { // Search Extra for OPT RRs
		if opt, ok := rr.(*dns.OPT); ok {
			for _, subOpt := range opt.Option { // Search OPT RR for ECS
				if e, ok := subOpt.(*dns.EDNS0_PADDING); ok {
					return len(e.Padding)
				}
			}
		}
	}

	return -1
}

// PadAndPack creates an EDNS0_PADDING sub-option which is added to the OPT in dns.Msg.Extra. If no
// OPT exists, one is created. The end result is a padded, packed message that is a size modulo of
// the provided size parameter. Padding is recommended by RFC8467. In particular it recommends
// queries be padded "to the closest multiple of 128 octets" and responses be padded to "a multiple
// of 468 octets". (Interesting that they don't say "closest multiple" for the response but I think
// that's just editorial imprecision.)
//
// If the message has an existing padding option it is removed as padding is deemed to serve a
// hop-by-hop purpose thus any pre-existing padding has already served its protective and signally
// purpose when it arrived here.
//
// This function also calls dns.Pack() to ensure that the caller is incapable of making subsequent
// modifications to the message which would obviously invalidate the carefully selected padding
// sizes.
//
// Even if the current message is an exact modulo length (and thus apparently not requiring any
// padding) we still add a padding option because that option is used to signal the remote end to
// add padding in response.
//
// WARNING: dns.Msg.Len() and dns.Msg.Pack() only work properly with well-formed DNS messages so
// this function also only works with properly formed DNS messages. In particular Len() and Pack()
// can result in different lengths.
//
// Returns the dns.Pack() byte array or an error.
func PadAndPack(msg *dns.Msg, moduloSize uint) ([]byte, error) {
	if moduloSize < 1 || moduloSize > consts.MaximumViableDNSMessage {
		return nil, fmt.Errorf("PadAndPack: Modulo size %d is not in range 1-%d",
			moduloSize, consts.MaximumViableDNSMessage)
	}
	var optRR *dns.OPT
	if len(msg.Extra) > 0 {
		RemoveEDNS0FromOPT(msg, dns.EDNS0PADDING) // Remove any existing PADDING
		if len(msg.Extra) > 0 {
			optRR = FindOPT(msg) // Use pre-existing OPT if present
		}
	}
	if optRR == nil { // If no pre-existing, create a fresh one
		optRR = NewOPT()
		msg.Extra = append(msg.Extra, optRR)
	}

	// We now have a guaranteed OPT RR with no existing padding. Add a zero length padding
	// option which adds the overhead of padding so we can correctly calculate the current
	// packed message length to deduce how much padding is needed to bring it up to the
	// recommended size modulo.

	padding := &dns.EDNS0_PADDING{Padding: make([]byte, 0)}
	optRR.Option = append(optRR.Option, padding)

	mLen := msg.Len() // This is an expensive call so cache the value

	extraPadding := moduloSize - (uint(mLen) % moduloSize)

	// It *may* be that the message is exactly the right size with a zero length padding
	// option. May as well avoid re-padding if we got lucky.
	if extraPadding > 0 {
		padding.Padding = make([]byte, extraPadding)
		optRR.Option[len(optRR.Option)-1] = padding // Replace original padding option with correct one
	}

	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("PadAndPack dns.Pack() failed: %s", err.Error())
	}

	// The message should have packed to the correct modulo size, but let's check just to be
	// sure as the msg.Len() function does not follow the same code path as the msg.Pack()
	// function thus there is a discrepancy risk.
	if uint(len(packed))%moduloSize != 0 { // Check that we did good!
		return nil, fmt.Errorf("PadAndPack dns.Pack() created unexpected length of %d with mod %d",
			len(packed), moduloSize)
	}

	return packed, nil
}
