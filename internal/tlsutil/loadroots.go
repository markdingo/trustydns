package tlsutil

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

// loadroots loads all the indicated root CA files and returns an x509.CertPool. If neither roots or
// other CAs are indicated an empty pool is returned which will tell a tls.Config *not* to try and
// retrieve the roots itself.
//
// Returns a (possibly empty) c509.CertPool or error
func loadroots(useSystemRoots bool, otherCAFiles []string) (*x509.CertPool, error) {
	var pool *x509.CertPool
	if useSystemRoots {
		var err error
		pool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("tlsutil:loadroots:systemRoots failed: %s", err.Error())
		}
	} else {
		pool = x509.NewCertPool()
	}

	// Load the other CA files

	for _, caFile := range otherCAFiles {
		asn1Data, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("tlsutil:loadroots:otherCA failed: %s", err.Error())
		}

		if !pool.AppendCertsFromPEM(asn1Data) {
			return nil, fmt.Errorf("tlsutil:loadroots:appendCerts failed to add %s", caFile)
		}
	}

	return pool, nil
}
