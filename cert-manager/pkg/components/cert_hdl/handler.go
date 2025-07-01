package cert_hdl

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	keyFile  = "client.key"
	certFile = "client.crt"
)

const (
	dirPerm      = 0775
	keyFilePerm  = 0600
	certFilePerm = 0660
)

const (
	algoRSA     = "RSA"
	algoECDH    = "ECDH"
	algoECDSA   = "ECDSA"
	algoEd25519 = "Ed25519"
)

type Handler struct {
	caCltToken certificateAuthorityClient
	caCltCert  certificateAuthorityClient
	config     Config
	mu         sync.RWMutex
}

func New(caClientToken, caClientCert certificateAuthorityClient, config Config) *Handler {
	return &Handler{
		caCltToken: caClientToken,
		caCltCert:  caClientCert,
		config:     config,
	}
}

func (h *Handler) Init() error {
	err := os.MkdirAll(h.config.WorkDirPath, dirPerm)
	if err != nil {
		return err
	}
	return h.deploy()
}

func (h *Handler) Info(_ context.Context) (models.CertInfo, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	block, err := readPemFile(path.Join(h.config.WorkDirPath, certFile))
	if err != nil {
		if os.IsNotExist(err) {
			return models.CertInfo{}, models.NewNotFoundError(errors.New("certificate not found"))
		}
		return models.CertInfo{}, models.NewInternalError(err)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return models.CertInfo{}, models.NewInternalError(err)
	}
	return models.CertInfo{
		Version:            cert.Version,
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		Issuer:             newDN(cert.Issuer),
		Subject:            newDN(cert.Subject),
		SubjectAltNames:    cert.DNSNames,
	}, nil
}

func (h *Handler) New(_ context.Context, dn models.DistinguishedName, subAltNames []string, validityPeriod time.Duration, userPrivateKey []byte, token string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var privateKey any
	var err error
	if len(userPrivateKey) > 0 {
		pemBlock, _ := pem.Decode(userPrivateKey)
		if pemBlock == nil {
			return models.NewInvalidInputError(errors.New("no pem formatted block found"))
		}
		privateKey, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return models.NewInvalidInputError(err)
		}
		if pk, ok := privateKey.(*rsa.PrivateKey); ok {
			if err = pk.Validate(); err != nil {
				return models.NewInvalidInputError(err)
			}
		}
	} else {
		privateKey, err = newPrivateKey(h.config.PrivateKeyAlgorithm)
		if err != nil {
			return models.NewInternalError(err)
		}
	}
	keyBlock, err := privateKeyToPemBlock(privateKey)
	if err != nil {
		return models.NewInternalError(err)
	}
	cert, err := getNewCert(h.caCltToken, newPkixName(dn), subAltNames, validityPeriod, privateKey, token)
	if err != nil {
		return models.NewInternalError(err)
	}
	if err = writeKeyAndCertPemFiles(h.config.WorkDirPath, keyBlock, certToPemBlock(cert)); err != nil {
		return models.NewInternalError(err)
	}
	if err = h.deploy(); err != nil {
		return models.NewInternalError(err)
	}
	return nil
}

func (h *Handler) Renew(_ context.Context, dn models.DistinguishedName, subAltNames []string, validityPeriod time.Duration, token string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	keyBlock, err := readPemFile(path.Join(h.config.WorkDirPath, keyFile))
	if err != nil {
		return models.NewInternalError(err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return models.NewInternalError(err)
	}
	caClt := h.caCltCert
	if token != "" {
		caClt = h.caCltToken
	}
	cert, err := getNewCert(caClt, newPkixName(dn), subAltNames, validityPeriod, privateKey, token)
	if err != nil {
		return models.NewInternalError(err)
	}
	certPath := path.Join(h.config.WorkDirPath, certFile)
	certBkPath, err := createBackupFile(certPath, certFilePerm)
	if err != nil {
		return models.NewInternalError(err)
	}
	if err = writePemFile(certPath, certToPemBlock(cert), certFilePerm); err != nil {
		if e := copyFile(certBkPath, certPath, certFilePerm); e != nil {
			err = errors.Join(err, e)
		}
		return models.NewInternalError(err)
	}
	if err = h.deploy(); err != nil {
		return models.NewInternalError(err)
	}
	if _, err = caClt.Revoke(cert, "superseded", &token); err != nil {
		return models.NewInternalError(err)
	}
	return nil
}

func (h *Handler) Revoke(_ context.Context, reason, token string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	certPath := path.Join(h.config.WorkDirPath, certFile)
	block, err := readPemFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return models.NewNotFoundError(errors.New("certificate not found"))
		}
		return models.NewInternalError(err)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return models.NewInternalError(err)
	}
	if err = os.Remove(certPath); err != nil {
		return models.NewInternalError(err)
	}
	if err = os.Remove(path.Join(h.config.WorkDirPath, keyFile)); err != nil {
		return models.NewInternalError(err)
	}
	if err = copyKeyAndCertFiles(h.config.DummyDirPath, h.config.TargetDirPath); err != nil {
		return models.NewInternalError(err)
	}
	caClt := h.caCltCert
	if token != "" {
		caClt = h.caCltToken
	}
	if _, err = caClt.Revoke(cert, reason, &token); err != nil {
		return models.NewInternalError(err)
	}
	return nil
}

func (h *Handler) Deploy(_ context.Context) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.deploy()
}

func (h *Handler) deploy() error {
	wrkKey, wrkCrt, err := readKeyAndCertBytes(h.config.WorkDirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	diff := false
	tgtKey, tgtCrt, err := readKeyAndCertBytes(h.config.TargetDirPath)
	if err != nil {
		if os.IsNotExist(err) {
			diff = true
		} else {
			return err
		}
	}
	if !bytes.Equal(wrkKey, tgtKey) || !bytes.Equal(wrkCrt, tgtCrt) {
		diff = true
	}
	if diff {
		return copyKeyAndCertFiles(h.config.WorkDirPath, h.config.TargetDirPath)
	}
	return nil
}

func getNewCert(client certificateAuthorityClient, dn pkix.Name, subAltNames []string, validityPeriod time.Duration, prvKey any, token string) (*x509.Certificate, error) {
	key, err := privateKeyForCA(prvKey)
	if err != nil {
		return nil, err
	}
	// following client method does not implement a timeout
	cert, _, err := client.NewCertFromKey(key, dn, subAltNames, validityPeriod, &token)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func newPrivateKey(algo string) (key any, err error) {
	switch strings.ToUpper(algo) {
	case algoRSA:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	case algoECDH:
		key, err = ecdh.P521().GenerateKey(rand.Reader)
	case algoECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case algoEd25519:
		key, _, err = ed25519.GenerateKey(rand.Reader)
	default:
		err = fmt.Errorf("algorithm '%s' not supported", algo)
	}
	return
}

func privateKeyForCA(key any) (*rsa.PrivateKey, error) {
	errFormat := "algorithm %s not supported by backend"
	switch pk := key.(type) {
	case *rsa.PrivateKey:
		return pk, nil
	case *ecdh.PrivateKey:
		return nil, fmt.Errorf(errFormat, algoECDH)
	case *ecdsa.PrivateKey:
		return nil, fmt.Errorf(errFormat, algoECDSA)
	case ed25519.PrivateKey:
		return nil, fmt.Errorf(errFormat, algoEd25519)
	default:
		return nil, errors.New("algorithm not supported")
	}
}

func newDN(n pkix.Name) models.DistinguishedName {
	return models.DistinguishedName{
		Country:            n.Country,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Locality:           n.Locality,
		Province:           n.Province,
		StreetAddress:      n.StreetAddress,
		PostalCode:         n.PostalCode,
		SerialNumber:       n.SerialNumber,
		CommonName:         n.CommonName,
	}
}

func newPkixName(dn models.DistinguishedName) pkix.Name {
	return pkix.Name{
		Country:            dn.Country,
		Organization:       dn.Organization,
		OrganizationalUnit: dn.OrganizationalUnit,
		Locality:           dn.Locality,
		Province:           dn.Province,
		StreetAddress:      dn.StreetAddress,
		PostalCode:         dn.PostalCode,
		SerialNumber:       dn.SerialNumber,
		CommonName:         dn.CommonName,
	}
}

func readKeyAndCertBytes(basePath string) ([]byte, []byte, error) {
	kb, err := os.ReadFile(path.Join(basePath, keyFile))
	if err != nil {
		return nil, nil, err
	}
	cb, err := os.ReadFile(path.Join(basePath, certFile))
	if err != nil {
		return nil, nil, err
	}
	return kb, cb, nil
}

func writeKeyAndCertPemFiles(basePath string, keyBlock *pem.Block, certBlock *pem.Block) error {
	keyBkPth, certBkPath, err := createKeyAndCertFileBackups(basePath)
	if err != nil {
		return err
	}
	keyPath := path.Join(basePath, keyFile)
	err = writePemFile(keyPath, keyBlock, keyFilePerm)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && keyBkPth != "" {
			if e := copyFile(keyBkPth, keyPath, keyFilePerm); e != nil {
				err = errors.Join(err, e)
			}
		}
	}()
	certPath := path.Join(basePath, certFile)
	err = writePemFile(certPath, certBlock, certFilePerm)
	if err != nil {
		if certBkPath != "" {
			if e := copyFile(certBkPath, certPath, certFilePerm); e != nil {
				err = errors.Join(err, e)
			}
		}
		return err
	}
	return nil
}

func copyKeyAndCertFiles(srcPath, targetPath string) error {
	keyBkPth, certBkPath, err := createKeyAndCertFileBackups(targetPath)
	if err != nil {
		return err
	}
	keyTgtPath := path.Join(targetPath, keyFile)
	err = copyFile(path.Join(srcPath, keyFile), keyTgtPath, keyFilePerm)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && keyBkPth != "" {
			if e := copyFile(keyBkPth, keyTgtPath, keyFilePerm); e != nil {
				err = errors.Join(err, e)
			}
		}
	}()
	certTgtPath := path.Join(targetPath, certFile)
	err = copyFile(path.Join(srcPath, certFile), certTgtPath, certFilePerm)
	if err != nil {
		if certBkPath != "" {
			if e := copyFile(certBkPath, certTgtPath, certFilePerm); e != nil {
				err = errors.Join(err, e)
			}
		}
		return err
	}
	return nil
}

func createKeyAndCertFileBackups(basePath string) (keyBackupPath string, certBackupPath string, err error) {
	keyBackupPath, err = createBackupFile(path.Join(basePath, keyFile), keyFilePerm)
	if err != nil {
		return "", "", err
	}
	certBackupPath, err = createBackupFile(path.Join(basePath, certFile), certFilePerm)
	if err != nil {
		return "", "", err
	}
	return
}

func privateKeyToPemBlock(key any) (*pem.Block, error) {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}, nil
}

func certToPemBlock(cert *x509.Certificate) *pem.Block {
	return &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
}

func readPemFile(p string) (*pem.Block, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return block, nil
}

func writePemFile(pth string, block *pem.Block, perm os.FileMode) error {
	file, err := os.OpenFile(pth, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}

func createBackupFile(pth string, perm os.FileMode) (string, error) {
	_, err := os.Stat(pth)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	bkPth := pth + ".bk"
	if err = copyFile(pth, bkPth, perm); err != nil {
		os.Remove(bkPth)
		return "", err
	}
	return bkPth, nil
}

func copyFile(srcPath, targetPath string, perm os.FileMode) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	targetFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer targetFile.Close()
	_, err = io.Copy(targetFile, srcFile)
	if err != nil {
		return err
	}
	return nil
}
