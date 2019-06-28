package tlsutil

import (
	"crypto/tls"
	"fmt"
)

const (
	myPrefix = "tlsutil:NewServerTLSConfig"
)

// NewServerTLSConfig is a helper wrapper which creates a tls.Config for a server-side
// connection. If either root CAs are indicated or other CAs are supplied, client verification is
// enabled. If server keys and cert files are supplied, they are loaded as server-side certificates
// to present to the client. The matching certs and keys must be in the same array position,
// obviously enough.
//
// Returns a tls.Config or an error.
func NewServerTLSConfig(useSystemCAs bool, otherCAFiles []string, certs, keys []string) (*tls.Config, error) {
	verifyClient := useSystemCAs || len(otherCAFiles) > 0 // Will verify if any roots are supplied
	cfg := &tls.Config{}
	if verifyClient { // Need a cert pool if we're using system or other CAs
		pool, err := loadroots(useSystemCAs, otherCAFiles)
		if err != nil {
			return nil, fmt.Errorf("%s:%s", myPrefix, err.Error())
		}
		cfg.ClientCAs = pool                            // Set client verification roots
		cfg.ClientAuth = tls.RequireAndVerifyClientCert // ... and insist on legit client certs
	}

	if len(certs) != len(keys) {
		return nil, fmt.Errorf("%s:Certificate file count (%d) and key file count (%d) don't match",
			myPrefix, len(certs), len(keys))
	}

	cfg.Certificates = make([]tls.Certificate, 0, len(certs))
	for ix, certFile := range certs {
		keyFile := keys[ix]
		if len(certFile) == 0 {
			return nil, fmt.Errorf("%s:Empty string Certificate file @ %d not allowed", myPrefix, ix)
		}
		if len(keyFile) == 0 {
			return nil, fmt.Errorf("%s:Empty string Key file @ %d not allowed", myPrefix, ix)
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("%s:tls.LoadX509KeyPair:%s for %s and %s",
				myPrefix, err.Error(), certFile, keyFile)
		}
		cfg.Certificates = append(cfg.Certificates, cert)
	}

	// Create the mapping between the certificate's CN and the certificate so that a single TLS
	// listener can accept connections for multiple domains. Callers can consult the
	// cfg.NameToCertificate map to determine which CNs have been mapped.

	cfg.BuildNameToCertificate()

	return cfg, nil
}
