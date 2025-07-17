package cert

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
	"github.com/SENERGY-Platform/go-service-base/struct-logger/attributes"
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/cert"
	helper_file "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/components/helper/file"
	models_error "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/error"
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
	dirPerm      = 0666
	keyFilePerm  = 0600
	certFilePerm = 0660
)

type Handler struct {
	caClt  certificateAuthorityClient
	config Config
	mu     sync.RWMutex
}

func New(caClient certificateAuthorityClient, config Config) *Handler {
	return &Handler{
		caClt:  caClient,
		config: config,
	}
}

func (h *Handler) Init() error {
	return os.MkdirAll(h.config.WorkDirPath, dirPerm)
}

func (h *Handler) Info(_ context.Context) (models_cert.Info, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	block, err := readPemFile(path.Join(h.config.WorkDirPath, certFile))
	if err != nil {
		if os.IsNotExist(err) {
			return models_cert.Info{}, models_error.NoCertificateErr
		}
		return models_cert.Info{}, err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return models_cert.Info{}, err
	}
	return models_cert.Info{
		Version:            cert.Version,
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		Issuer:             newDN(cert.Issuer),
		Subject:            newDN(cert.Subject),
		SubjectAltNames:    getSubjAltNames(cert),
	}, nil
}

func (h *Handler) New(_ context.Context, dn models_cert.DistinguishedName, subAltNames []string, validityPeriod time.Duration, userPrivateKey []byte, token string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var privateKey any
	var err error
	if len(userPrivateKey) > 0 {
		pemBlock, _ := pem.Decode(userPrivateKey)
		if pemBlock == nil {
			return errors.New("no pem formatted block found")
		}
		privateKey, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return err
		}
		if pk, ok := privateKey.(*rsa.PrivateKey); ok {
			if err = pk.Validate(); err != nil {
				return err
			}
		}
	} else {
		privateKey, err = newPrivateKey(h.config.PrivateKeyAlgorithm)
		if err != nil {
			return err
		}
	}
	keyBlock, err := privateKeyToPemBlock(privateKey)
	if err != nil {
		return err
	}
	cert, err := h.caClt.NewCertFromKey(privateKey, newPkixName(dn), subAltNames, validityPeriod, token)
	if err != nil {
		return err
	}
	if err = writeKeyAndCertPemFiles(h.config.WorkDirPath, keyBlock, certToPemBlock(cert)); err != nil {
		return err
	}
	if err = h.deploy(); err != nil {
		return err
	}
	return nil
}

func (h *Handler) Renew(_ context.Context, dn models_cert.DistinguishedName, subAltNames []string, validityPeriod time.Duration, token string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	certBlock, err := readPemFile(path.Join(h.config.WorkDirPath, certFile))
	if err != nil {
		return err
	}
	oldCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	keyBlock, err := readPemFile(path.Join(h.config.WorkDirPath, keyFile))
	if err != nil {
		return err
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	newCert, err := h.caClt.NewCertFromKey(privateKey, newPkixName(dn), subAltNames, validityPeriod, token)
	if err != nil {
		return err
	}
	certPath := path.Join(h.config.WorkDirPath, certFile)
	certBkPath, err := helper_file.BackupFile(certPath, certFilePerm)
	if err != nil {
		return err
	}
	if err = writePemFile(certPath, certToPemBlock(newCert), certFilePerm); err != nil {
		if e := helper_file.Copy(certBkPath, certPath, certFilePerm); e != nil {
			err = errors.Join(err, e)
		}
		return err
	}
	if err = h.deploy(); err != nil {
		return err
	}
	if err = h.caClt.Revoke(oldCert, "superseded", token); err != nil {
		logger.Error("revoking certificate failed", attributes.ErrorKey, err)
	}
	return nil
}

func (h *Handler) Clear(_ context.Context, reason, token string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	certPath := path.Join(h.config.WorkDirPath, certFile)
	block, err := readPemFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return models_error.NoCertificateErr
		}
		return err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if err = os.Remove(certPath); err != nil {
		return err
	}
	if err = os.Remove(path.Join(h.config.WorkDirPath, keyFile)); err != nil {
		return err
	}
	if err = copyKeyAndCertFiles(h.config.DummyDirPath, h.config.TargetDirPath); err != nil {
		return err
	}
	if err = h.caClt.Revoke(cert, reason, token); err != nil {
		logger.Error("revoking certificate failed", attributes.ErrorKey, err)
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

func newPrivateKey(algo string) (key any, err error) {
	switch strings.ToUpper(algo) {
	case AlgoRSA:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	case AlgoECDH:
		key, err = ecdh.P521().GenerateKey(rand.Reader)
	case AlgoECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case AlgoEd25519:
		key, _, err = ed25519.GenerateKey(rand.Reader)
	default:
		err = fmt.Errorf("algorithm '%s' not supported", algo)
	}
	return
}

func newDN(n pkix.Name) models_cert.DistinguishedName {
	return models_cert.DistinguishedName{
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

func newPkixName(dn models_cert.DistinguishedName) pkix.Name {
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
			if e := helper_file.Copy(keyBkPth, keyPath, keyFilePerm); e != nil {
				err = errors.Join(err, e)
			}
		}
	}()
	certPath := path.Join(basePath, certFile)
	err = writePemFile(certPath, certBlock, certFilePerm)
	if err != nil {
		if certBkPath != "" {
			if e := helper_file.Copy(certBkPath, certPath, certFilePerm); e != nil {
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
	err = helper_file.Copy(path.Join(srcPath, keyFile), keyTgtPath, keyFilePerm)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && keyBkPth != "" {
			if e := helper_file.Copy(keyBkPth, keyTgtPath, keyFilePerm); e != nil {
				err = errors.Join(err, e)
			}
		}
	}()
	certTgtPath := path.Join(targetPath, certFile)
	err = helper_file.Copy(path.Join(srcPath, certFile), certTgtPath, certFilePerm)
	if err != nil {
		if certBkPath != "" {
			if e := helper_file.Copy(certBkPath, certTgtPath, certFilePerm); e != nil {
				err = errors.Join(err, e)
			}
		}
		return err
	}
	return nil
}

func createKeyAndCertFileBackups(basePath string) (keyBackupPath string, certBackupPath string, err error) {
	keyBackupPath, err = helper_file.BackupFile(path.Join(basePath, keyFile), keyFilePerm)
	if err != nil {
		return "", "", err
	}
	certBackupPath, err = helper_file.BackupFile(path.Join(basePath, certFile), certFilePerm)
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

func getSubjAltNames(cert *x509.Certificate) models_cert.SANs {
	var sans models_cert.SANs
	sans.DNSNames = append(sans.DNSNames, cert.DNSNames...)
	sans.EmailAddresses = append(sans.EmailAddresses, cert.EmailAddresses...)
	for _, address := range cert.IPAddresses {
		sans.IPAddresses = append(sans.IPAddresses, address.String())
	}
	for _, uri := range cert.URIs {
		sans.URIs = append(sans.URIs, uri.String())
	}
	return sans
}
