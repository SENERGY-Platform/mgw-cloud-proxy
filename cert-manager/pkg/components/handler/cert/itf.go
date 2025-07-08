package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

type certificateAuthorityClient interface {
	NewCertFromKey(key any, subj pkix.Name, subAltNames []string, validityPeriod time.Duration, token string) (*x509.Certificate, error)
	Revoke(cert *x509.Certificate, reason string, token string) error
}
