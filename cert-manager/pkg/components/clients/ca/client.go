package ca

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/SENERGY-Platform/cert-certificate-authority/pkg/client"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	tokenClt client.Client
	certClt  client.Client
}

func New(tokenBaseUrl, certBaseUrl string) (*Client, error) {
	tokenBaseUrl, err := url.JoinPath(tokenBaseUrl, "ca")
	if err != nil {
		return nil, err
	}
	certBaseUrl, err = url.JoinPath(certBaseUrl, "ca")
	if err != nil {
		return nil, err
	}
	return &Client{
		tokenClt: client.NewClient(tokenBaseUrl),
		certClt:  client.NewClient(certBaseUrl),
	}, nil
}

func (c *Client) NewCertFromKey(key any, subj pkix.Name, subAltNames []string, validityPeriod time.Duration, token string) (*x509.Certificate, error) {
	pKey, err := privateKeyForCA(key)
	if err != nil {
		return nil, err
	}
	clt := c.certClt
	if token != "" {
		clt = c.tokenClt
	}
	// following client method does not implement a timeout
	cert, sc, err := clt.NewCertFromKey(pKey, subj, subAltNames, validityPeriod, &token)
	if err != nil {
		return nil, err
	}
	if sc != http.StatusOK {
		return nil, fmt.Errorf("%d - %s", sc, http.StatusText(sc))
	}
	return cert, nil
}

func (c *Client) Revoke(cert *x509.Certificate, reason string, token string) error {
	clt := c.certClt
	if token != "" {
		clt = c.tokenClt
	}
	// following client method does not implement a timeout
	sc, err := clt.Revoke(cert, reason, &token)
	if err != nil {
		return err
	}
	if sc != http.StatusOK {
		return fmt.Errorf("%d - %s", sc, http.StatusText(sc))
	}
	return nil
}

func privateKeyForCA(key any) (*rsa.PrivateKey, error) {
	errFormat := "algorithm %s not supported by backend"
	switch pk := key.(type) {
	case *rsa.PrivateKey:
		return pk, nil
	case *ecdh.PrivateKey:
		return nil, fmt.Errorf(errFormat, "ECDH")
	case *ecdsa.PrivateKey:
		return nil, fmt.Errorf(errFormat, "ECDSA")
	case ed25519.PrivateKey:
		return nil, fmt.Errorf(errFormat, "Ed25519")
	default:
		return nil, errors.New("algorithm not supported")
	}
}
