// tlsutil is a helper package to manage tls key and cert settings
package tlsutil

import (
	"crypto/tls"
	"errors"
)

// NewClientTLSConfig is a helper wrapper which creates a tls.Config for a client-side HTTPS
// connection. If either root CAs are indicated or other CAs are supplied, server verification is
// enabled. If client key and cert files are supplied, they are loaded as client-side certificates
// to present to the server. Both key and cert must be present or both most be absent.
//
// Returns a tls.Config or an error.
func NewClientTLSConfig(useSystemCAs bool, otherCAFiles []string, clientCertFile, clientKeyFile string) (*tls.Config, error) {
	verifyServer := useSystemCAs || len(otherCAFiles) > 0 // Will verify if any roots are supplied
	cfg := &tls.Config{InsecureSkipVerify: !verifyServer} // Ask to verify server if we have any CAs
	if verifyServer {                                     // Need a cert pool if we're using system or other CAs
		pool, err := loadroots(useSystemCAs, otherCAFiles)
		if err != nil {
			return nil, errors.New("tlsutil:NewClientTLSConfig:" + err.Error())
		}
		cfg.RootCAs = pool // Set server verification roots
	}

	// We must have both or neither, not one or the other.
	if len(clientCertFile) > 0 && len(clientKeyFile) == 0 {
		return nil, errors.New("tlsutil:NewClientTLSConfig Client key file missing when cert file present")
	}
	if len(clientCertFile) == 0 && len(clientKeyFile) > 0 {
		return nil, errors.New("tlsutil:NewClientTLSConfig Client cert file missing when key file present")
	}

	if len(clientCertFile) == 0 {
		return cfg, nil
	}

	var err error
	cfg.Certificates = make([]tls.Certificate, 1)
	cfg.Certificates[0], err = tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, errors.New("tlsutil:NewClientTLSConfig:tls.LoadX509KeyPair" + err.Error())
	}

	return cfg, nil
}
