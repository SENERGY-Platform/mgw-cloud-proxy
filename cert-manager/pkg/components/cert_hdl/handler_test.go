package cert_hdl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/file_util"
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/cert"
	"log/slog"
	"os"
	"path"
	"reflect"
	"testing"
	"time"
)

func TestHandler_Deploy(t *testing.T) {
	InitLogger(slog.Default())
	workDir := t.TempDir()
	targetDir := t.TempDir()
	h := New(nil, nil, Config{
		WorkDirPath:   workDir,
		TargetDirPath: targetDir,
	})
	t.Run("no files in target and work dir", func(t *testing.T) {
		err := h.Deploy(context.Background())
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("files in work dir and no files in target dir", func(t *testing.T) {
		err := os.WriteFile(path.Join(workDir, certFile), []byte("cert"), certFilePerm)
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(path.Join(workDir, keyFile), []byte("key"), keyFilePerm)
		if err != nil {
			t.Fatal(err)
		}
		err = h.Deploy(context.Background())
		if err != nil {
			t.Error(err)
		}
		b, err := os.ReadFile(path.Join(targetDir, certFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(b, []byte("cert")) {
			t.Error("cert file does not match")
		}
		b, err = os.ReadFile(path.Join(targetDir, keyFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(b, []byte("key")) {
			t.Error("key file does not match")
		}
	})
	t.Run("files in work and target dir with diff", func(t *testing.T) {
		err := os.WriteFile(path.Join(workDir, certFile), []byte("cert2"), certFilePerm)
		if err != nil {
			t.Fatal(err)
		}
		err = h.Deploy(context.Background())
		if err != nil {
			t.Error(err)
		}
		b, err := os.ReadFile(path.Join(targetDir, certFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(b, []byte("cert2")) {
			t.Error("cert file does not match")
		}
		b, err = os.ReadFile(path.Join(targetDir, keyFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(b, []byte("key")) {
			t.Error("key file does not match")
		}
	})
}

func TestHandler_New(t *testing.T) {
	InitLogger(slog.Default())
	t.Run("gen private key", func(t *testing.T) {
		workDir := t.TempDir()
		targetDir := t.TempDir()
		mockClient := &caClientMock{
			Subject:    pkix.Name{SerialNumber: "test"},
			Hostnames:  []string{"test"},
			Expiration: time.Second,
			UseToken:   true,
			Token:      "test",
			T:          t,
		}
		h := New(mockClient, nil, Config{
			WorkDirPath:         workDir,
			TargetDirPath:       targetDir,
			PrivateKeyAlgorithm: algoRSA,
		})
		err := h.New(context.Background(), models_cert.DistinguishedName{SerialNumber: "test"}, []string{"test"}, time.Second, nil, "test")
		if err != nil {
			t.Error(err)
		}
		b, err := os.ReadFile(path.Join(workDir, keyFile))
		if err != nil {
			t.Error(err)
		}
		keyBlock, _ := pem.Decode(b)
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !mockClient.PrivateKey.Equal(key.(*rsa.PrivateKey)) {
			t.Error("private keys don't match")
		}
		a, err := os.ReadFile(path.Join(workDir, certFile))
		if err != nil {
			t.Error(err)
		}
		b, err = os.ReadFile(path.Join("./test", certFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(a, b) {
			t.Error("certificates don't match")
		}
		_, err = os.Stat(path.Join(targetDir, certFile))
		if err != nil {
			t.Error(err)
		}
		_, err = os.Stat(path.Join(targetDir, keyFile))
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("provide private key", func(t *testing.T) {
		rk, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Fatal(err)
		}
		kb, err := x509.MarshalPKCS8PrivateKey(rk)
		if err != nil {
			t.Fatal(err)
		}
		pb := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: kb,
		})
		workDir := t.TempDir()
		targetDir := t.TempDir()
		mockClient := &caClientMock{
			Subject:    pkix.Name{SerialNumber: "test"},
			Hostnames:  []string{"test"},
			Expiration: time.Second,
			UseToken:   true,
			Token:      "test",
			T:          t,
		}
		h := New(mockClient, nil, Config{
			WorkDirPath:   workDir,
			TargetDirPath: targetDir,
		})
		err = h.New(context.Background(), models_cert.DistinguishedName{SerialNumber: "test"}, []string{"test"}, time.Second, pb, "test")
		if err != nil {
			t.Error(err)
		}
		b, err := os.ReadFile(path.Join(workDir, keyFile))
		if err != nil {
			t.Error(err)
		}
		keyBlock, _ := pem.Decode(b)
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !rk.Equal(key.(*rsa.PrivateKey)) {
			t.Error("private keys don't match")
		}
		a, err := os.ReadFile(path.Join(workDir, certFile))
		if err != nil {
			t.Error(err)
		}
		b, err = os.ReadFile(path.Join("./test", certFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(a, b) {
			t.Error("certificates don't match")
		}
		_, err = os.Stat(path.Join(targetDir, certFile))
		if err != nil {
			t.Error(err)
		}
		_, err = os.Stat(path.Join(targetDir, keyFile))
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("error", func(t *testing.T) {
		workDir := t.TempDir()
		targetDir := t.TempDir()
		mockClient := &caClientMock{
			Subject:    pkix.Name{SerialNumber: "test"},
			Hostnames:  []string{"test"},
			Expiration: time.Second,
			UseToken:   true,
			Token:      "test",
			T:          t,
			Err:        errors.New("test"),
		}
		h := New(mockClient, nil, Config{
			WorkDirPath:         workDir,
			TargetDirPath:       targetDir,
			PrivateKeyAlgorithm: algoRSA,
		})
		err := h.New(context.Background(), models_cert.DistinguishedName{SerialNumber: "test"}, []string{"test"}, time.Second, nil, "test")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestHandler_Renew(t *testing.T) {
	t.Run("auth with cert", func(t *testing.T) {
		workDir := t.TempDir()
		targetDir := t.TempDir()
		err := file_util.Copy(path.Join("./test", keyFile), path.Join(workDir, keyFile), keyFilePerm)
		if err != nil {
			t.Fatal(err)
		}
		mockClient := &caClientMock{
			Subject:    pkix.Name{SerialNumber: "test"},
			Hostnames:  []string{"test"},
			Expiration: time.Second,
			Reason:     "superseded",
			T:          t,
		}
		h := New(nil, mockClient, Config{
			WorkDirPath:   workDir,
			TargetDirPath: targetDir,
		})
		err = h.Renew(context.Background(), models_cert.DistinguishedName{SerialNumber: "test"}, []string{"test"}, time.Second, "")
		if err != nil {
			t.Error(err)
		}
		a, err := os.ReadFile(path.Join(workDir, certFile))
		if err != nil {
			t.Error(err)
		}
		b, err := os.ReadFile(path.Join("./test", certFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(a, b) {
			t.Error("certificates don't match")
		}
		_, err = os.Stat(path.Join(targetDir, certFile))
		if err != nil {
			t.Error(err)
		}
		_, err = os.Stat(path.Join(targetDir, keyFile))
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("auth with token", func(t *testing.T) {
		workDir := t.TempDir()
		targetDir := t.TempDir()
		err := file_util.Copy(path.Join("./test", keyFile), path.Join(workDir, keyFile), keyFilePerm)
		if err != nil {
			t.Fatal(err)
		}
		mockClient := &caClientMock{
			Subject:    pkix.Name{SerialNumber: "test"},
			Hostnames:  []string{"test"},
			Expiration: time.Second,
			Reason:     "superseded",
			UseToken:   true,
			Token:      "test",
			T:          t,
		}
		h := New(mockClient, nil, Config{
			WorkDirPath:   workDir,
			TargetDirPath: targetDir,
		})
		err = h.Renew(context.Background(), models_cert.DistinguishedName{SerialNumber: "test"}, []string{"test"}, time.Second, "test")
		if err != nil {
			t.Error(err)
		}
		a, err := os.ReadFile(path.Join(workDir, certFile))
		if err != nil {
			t.Error(err)
		}
		b, err := os.ReadFile(path.Join("./test", certFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(a, b) {
			t.Error("certificates don't match")
		}
		_, err = os.Stat(path.Join(targetDir, certFile))
		if err != nil {
			t.Error(err)
		}
		_, err = os.Stat(path.Join(targetDir, keyFile))
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("error", func(t *testing.T) {
		workDir := t.TempDir()
		targetDir := t.TempDir()
		err := file_util.Copy(path.Join("./test", keyFile), path.Join(workDir, keyFile), keyFilePerm)
		if err != nil {
			t.Fatal(err)
		}
		mockClient := &caClientMock{
			Subject:    pkix.Name{SerialNumber: "test"},
			Hostnames:  []string{"test"},
			Expiration: time.Second,
			Reason:     "superseded",
			T:          t,
			Err:        errors.New("test"),
		}
		h := New(nil, mockClient, Config{
			WorkDirPath:   workDir,
			TargetDirPath: targetDir,
		})
		err = h.Renew(context.Background(), models_cert.DistinguishedName{SerialNumber: "test"}, []string{"test"}, time.Second, "")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestHandler_Clear(t *testing.T) {
	InitLogger(slog.Default())
	t.Run("auth with cert", func(t *testing.T) {
		workDir := t.TempDir()
		targetDir := t.TempDir()
		err := file_util.Copy(path.Join("./test", keyFile), path.Join(workDir, keyFile), keyFilePerm)
		if err != nil {
			t.Fatal(err)
		}
		err = file_util.Copy(path.Join("./test", certFile), path.Join(workDir, certFile), certFilePerm)
		if err != nil {
			t.Fatal(err)
		}
		mockClient := &caClientMock{
			Subject:    pkix.Name{SerialNumber: "test"},
			Hostnames:  []string{"test"},
			Expiration: time.Second,
			Reason:     "unspecified",
			T:          t,
		}
		h := New(nil, mockClient, Config{
			WorkDirPath:   workDir,
			TargetDirPath: targetDir,
			DummyDirPath:  "./test",
		})
		err = h.Clear(context.Background(), "unspecified", "")
		if err != nil {
			t.Error(err)
		}
		_, err = os.Stat(path.Join(workDir, certFile))
		if err == nil {
			t.Error("expected error")
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		_, err = os.Stat(path.Join(workDir, keyFile))
		if err == nil {
			t.Error("expected error")
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		certA, err := os.ReadFile(path.Join("./test", certFile))
		if err != nil {
			t.Error(err)
		}
		certB, err := os.ReadFile(path.Join(targetDir, certFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(certB, certA) {
			t.Error("cert file does not match")
		}
		keyA, err := os.ReadFile(path.Join("./test", keyFile))
		if err != nil {
			t.Error(err)
		}
		keyB, err := os.ReadFile(path.Join(targetDir, keyFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(keyB, keyA) {
			t.Error("key file does not match")
		}
	})
	t.Run("auth with token", func(t *testing.T) {
		workDir := t.TempDir()
		targetDir := t.TempDir()
		err := file_util.Copy(path.Join("./test", keyFile), path.Join(workDir, keyFile), keyFilePerm)
		if err != nil {
			t.Fatal(err)
		}
		err = file_util.Copy(path.Join("./test", certFile), path.Join(workDir, certFile), certFilePerm)
		if err != nil {
			t.Fatal(err)
		}
		mockClient := &caClientMock{
			Subject:    pkix.Name{SerialNumber: "test"},
			Hostnames:  []string{"test"},
			Expiration: time.Second,
			Reason:     "unspecified",
			UseToken:   true,
			Token:      "test",
			T:          t,
		}
		h := New(mockClient, nil, Config{
			WorkDirPath:   workDir,
			TargetDirPath: targetDir,
			DummyDirPath:  "./test",
		})
		err = h.Clear(context.Background(), "unspecified", "test")
		if err != nil {
			t.Error(err)
		}
		_, err = os.Stat(path.Join(workDir, certFile))
		if err == nil {
			t.Error("expected error")
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		_, err = os.Stat(path.Join(workDir, keyFile))
		if err == nil {
			t.Error("expected error")
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		certA, err := os.ReadFile(path.Join("./test", certFile))
		if err != nil {
			t.Error(err)
		}
		certB, err := os.ReadFile(path.Join(targetDir, certFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(certB, certA) {
			t.Error("cert file does not match")
		}
		keyA, err := os.ReadFile(path.Join("./test", keyFile))
		if err != nil {
			t.Error(err)
		}
		keyB, err := os.ReadFile(path.Join(targetDir, keyFile))
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(keyB, keyA) {
			t.Error("key file does not match")
		}
	})
	t.Run("error", func(t *testing.T) {
		workDir := t.TempDir()
		targetDir := t.TempDir()
		mockClient := &caClientMock{
			Subject:    pkix.Name{SerialNumber: "test"},
			Hostnames:  []string{"test"},
			Expiration: time.Second,
			Reason:     "unspecified",
			T:          t,
			Err:        errors.New("test"),
		}
		h := New(nil, mockClient, Config{
			WorkDirPath:   workDir,
			TargetDirPath: targetDir,
			DummyDirPath:  "./test",
		})
		err := h.Clear(context.Background(), "unspecified", "")
		if err == nil {
			t.Error("expected error")
		}
	})
}

type caClientMock struct {
	PrivateKey *rsa.PrivateKey
	Subject    pkix.Name
	Hostnames  []string
	Expiration time.Duration
	UseToken   bool
	Token      string
	Reason     string
	Err        error
	CallCount  int
	T          *testing.T
}

func (m *caClientMock) NewCertFromKey(privateKey *rsa.PrivateKey, subj pkix.Name, hostnames []string, expiration time.Duration, token *string) (*x509.Certificate, int, error) {
	m.CallCount++
	if m.Err != nil {
		return nil, 0, m.Err
	}
	if privateKey == nil {
		m.T.Error("expected non nil private key")
	}
	m.PrivateKey = privateKey
	if !reflect.DeepEqual(subj, m.Subject) {
		m.T.Errorf("expected %v, got %v", m.Subject, subj)
	}
	if !reflect.DeepEqual(hostnames, m.Hostnames) {
		m.T.Errorf("expected %v, got %v", m.Hostnames, hostnames)
	}
	if expiration != m.Expiration {
		m.T.Errorf("expected %v, got %v", m.Expiration, expiration)
	}
	if m.UseToken && *token != m.Token {
		m.T.Errorf("expected %v, got %v", m.Token, *token)
	}
	b, err := os.ReadFile("./test/client.crt")
	if err != nil {
		m.T.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		m.T.Fatal("nil block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		m.T.Fatal(err)
	}
	return cert, 0, nil
}

func (m *caClientMock) Revoke(cert *x509.Certificate, reason string, token *string) (int, error) {
	m.CallCount++
	if m.Err != nil {
		return 0, m.Err
	}
	b, err := os.ReadFile(path.Join("./test", certFile))
	if err != nil {
		m.T.Fatal(err)
	}
	certBlock, _ := pem.Decode(b)
	tmp, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		m.T.Fatal(err)
	}
	if !cert.Equal(tmp) {
		m.T.Error("certificates don't match")
	}
	if reason != m.Reason {
		m.T.Errorf("expected %v, got %v", m.Reason, reason)
	}
	if m.UseToken && *token != m.Token {
		m.T.Errorf("expected %v, got %v", m.Token, *token)
	}
	return 0, nil
}
