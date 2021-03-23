/*
Package constants provides common values used across all trustydns packages. Usage is to call the
global Get() function which returns the Constants by value ensuring that any modifications made
(accidental or otherwise) will not affect other modules when they call Get().

Typically usage:

    consts := constants.Get()
    fmt.Println("I am", consts.ProxyProgramName, "based on", consts.RFC)

The primary reason for making this a constructed struct rather than the more typical const () block
is so that it can be fed directly into templating packages for printing usage messages.
*/
package constants

// Constants contains the system-wide constants
type Constants struct {
	DigProgramName    string
	ProxyProgramName  string // Package related constants
	ServerProgramName string
	Version           string
	PackageName       string
	PackageURL        string
	RFC               string

	HTTPSDefaultPort string // HTTP related constants
	AgeHeader        string

	AcceptHeader      string // Place in every request
	ContentTypeHeader string
	UserAgentHeader   string

	TrustyDurationHeader             string // Server header with time.Duration of server-side resolution
	TrustySynthesizeECSRequestHeader string // Proxy header with ipv4, ipv6 prefix length

	ConnectionValue    string
	Rfc8484AcceptValue string

	Rfc8484Path       string
	Rfc8484QueryParam string

	DNSDefaultPort          string // DNS Related constants
	MinimumViableDNSMessage uint   // MsgHdr + one Question with zero length name
	DNSTruncateThreshold    int    // A message larger than this size may be truncated unless EDNS0
	MaximumViableDNSMessage uint   // RFC8484 defines an upper limit
	Rfc8467ClientPadModulo  uint
	Rfc8467ServerPadModulo  uint

	DNSUDPTransport string // Suitable for the "net" package, but just to make sure we're
	DNSTCPTransport string // consistent across the whole package.
}

var readOnlyConstants *Constants

// createReadOnlyConstants creates a read-only copy of the Constants which is copied whenever a
// caller asks for the constants set. The main reason for returning a struct is so that callers can
// inspect and/or use packages that introspect - particularly */template packages.
func createReadOnlyConstants() {
	readOnlyConstants = &Constants{
		DigProgramName:    "trustydns-dig",
		ProxyProgramName:  "trustydns-proxy",
		ServerProgramName: "trustydns-server",
		Version:           "v0.2.1",
		PackageName:       "Trusty DNS Over HTTPS",
		PackageURL:        "https://github.com/markdingo/trustydns",
		RFC:               "RFC8484",

		HTTPSDefaultPort: "443",

		AgeHeader: "Age",

		AcceptHeader:      "Accept",
		ContentTypeHeader: "Content-Type",
		UserAgentHeader:   "User-Agent",

		TrustyDurationHeader:             "X-trustydns-Duration",
		TrustySynthesizeECSRequestHeader: "X-trustydns-Synth",

		ConnectionValue:    "Keep-Alive",
		Rfc8484AcceptValue: "application/dns-message",

		Rfc8484Path:       "/dns-query",
		Rfc8484QueryParam: "dns",

		DNSDefaultPort:          "53",
		MinimumViableDNSMessage: 16, // A legit binary DNS Message *cannot* be shorter than this
		DNSTruncateThreshold:    512,
		MaximumViableDNSMessage: 65535,
		Rfc8467ClientPadModulo:  128,
		Rfc8467ServerPadModulo:  468,

		DNSUDPTransport: "udp",
		DNSTCPTransport: "tcp",
	}
}

func init() {
	createReadOnlyConstants()
}

// Get returns a copy of the Constant struct. Return by value so internal values cannot be
// inadvertently changed by callers.
func Get() Constants {
	return *readOnlyConstants
}
