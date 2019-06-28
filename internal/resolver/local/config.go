package local

// Config is passed to the New() constructor.
type Config struct {
	ResolvConfPath string
	LocalDomains   []string // In addition to those found in the resolvConfPath

	// Caller can create their own Exchangers on our behalf
	NewDNSClientExchangerFunc func(net string) DNSClientExchanger
}
