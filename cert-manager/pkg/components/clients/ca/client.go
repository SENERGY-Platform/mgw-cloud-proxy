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
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/cert"
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
	cert, _, err := clt.NewCertFromKey(pKey, subj, subAltNames, validityPeriod, &token)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (c *Client) Revoke(cert *x509.Certificate, reason string, token string) error {
	clt := c.certClt
	if token != "" {
		clt = c.tokenClt
	}
	// following client method does not implement a timeout
	_, err := clt.Revoke(cert, reason, &token)
	if err != nil {
		return err
	}
	return nil
}

func privateKeyForCA(key any) (*rsa.PrivateKey, error) {
	errFormat := "algorithm %s not supported by backend"
	switch pk := key.(type) {
	case *rsa.PrivateKey:
		return pk, nil
	case *ecdh.PrivateKey:
		return nil, fmt.Errorf(errFormat, models_cert.AlgoECDH)
	case *ecdsa.PrivateKey:
		return nil, fmt.Errorf(errFormat, models_cert.AlgoECDSA)
	case ed25519.PrivateKey:
		return nil, fmt.Errorf(errFormat, models_cert.AlgoEd25519)
	default:
		return nil, errors.New("algorithm not supported")
	}
}
