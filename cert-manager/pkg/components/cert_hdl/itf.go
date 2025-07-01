package cert_hdl

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

type certificateAuthorityClient interface {
	NewCertFromKey(privateKey *rsa.PrivateKey, subj pkix.Name, hostnames []string, expiration time.Duration, token *string) (cert *x509.Certificate, errCode int, err error)
	Revoke(cert *x509.Certificate, reason string, token *string) (errCode int, err error)
}
