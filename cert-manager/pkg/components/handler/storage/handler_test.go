package storage

import (
	"context"
	"encoding/json"
	"errors"
	models_error "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/error"
	models_storage "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/storage"
	"os"
	"path"
	"reflect"
	"testing"
	"time"
)

func TestHandler_Init(t *testing.T) {
	wrkDir := t.TempDir()
	t.Run("no files", func(t *testing.T) {
		h := New(wrkDir)
		err := h.Init()
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("files exist", func(t *testing.T) {
		ca := models_storage.CertData{
			ValidityPeriod: time.Second,
			Created:        time.Time{},
		}
		cf, err := os.Create(path.Join(wrkDir, certDataFile))
		if err != nil {
			t.Fatal(err)
		}
		defer cf.Close()
		err = json.NewEncoder(cf).Encode(ca)
		if err != nil {
			t.Fatal(err)
		}
		na := models_storage.NetworkData{
			ID:     "id",
			UserID: "user_id",
			Added:  time.Time{},
		}
		nf, err := os.Create(path.Join(wrkDir, netDataFile))
		if err != nil {
			t.Fatal(err)
		}
		defer nf.Close()
		err = json.NewEncoder(nf).Encode(na)
		if err != nil {
			t.Fatal(err)
		}
		h := New(wrkDir)
		err = h.Init()
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(*h.certData, ca) {
			t.Errorf("expected '%v' got '%v'", ca, *h.certData)
		}
		if !reflect.DeepEqual(*h.networkData, na) {
			t.Errorf("expected '%v' got '%v'", na, *h.networkData)
		}
	})
}

func TestHandler_ReadCertificate(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		a := models_storage.CertData{
			ValidityPeriod: time.Second,
			Created:        time.Time{},
		}
		h := New("")
		h.certData = &a
		b, err := h.ReadCertificate(context.Background())
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(b, a) {
			t.Errorf("expected '%v' got '%v'", a, b)
		}
	})
	t.Run("does not exist", func(t *testing.T) {
		h := New("")
		_, err := h.ReadCertificate(context.Background())
		if err == nil {
			t.Error("expected error")
		}
		if !errors.Is(err, models_error.NoCertificateDataErr) {
			t.Errorf("expected '%v' got '%v'", models_error.NoCertificateDataErr, err)
		}
	})
}

func TestHandler_ReadNetwork(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		a := models_storage.NetworkData{
			ID:     "id",
			UserID: "user_id",
			Added:  time.Time{},
		}
		h := New("")
		h.networkData = &a
		b, err := h.ReadNetwork(context.Background())
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(b, a) {
			t.Errorf("expected '%v' got '%v'", a, b)
		}
	})
	t.Run("does not exist", func(t *testing.T) {
		h := New("")
		_, err := h.ReadNetwork(context.Background())
		if err == nil {
			t.Error("expected error")
		}
		if !errors.Is(err, models_error.NoNetworkDataErr) {
			t.Errorf("expected '%v' got '%v'", models_error.NoNetworkDataErr, err)
		}
	})
}

func TestHandler_WriteCertificate(t *testing.T) {
	wrkDir := t.TempDir()
	h := New(wrkDir)
	a := models_storage.CertData{
		ValidityPeriod: time.Second,
		Created:        time.Time{},
	}
	err := h.WriteCertificate(context.Background(), a)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(*h.certData, a) {
		t.Errorf("expected '%v' got '%v'", a, *h.certData)
	}
	f, err := os.Open(path.Join(wrkDir, certDataFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var b models_storage.CertData
	err = json.NewDecoder(f).Decode(&b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b, a) {
		t.Errorf("expected '%v' got '%v'", a, b)
	}
}

func TestHandler_WriteNetwork(t *testing.T) {
	wrkDir := t.TempDir()
	h := New(wrkDir)
	a := models_storage.NetworkData{
		ID:     "id",
		UserID: "user_id",
		Added:  time.Time{},
	}
	err := h.WriteNetwork(context.Background(), a)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(*h.networkData, a) {
		t.Errorf("expected '%v' got '%v'", a, *h.networkData)
	}
	f, err := os.Open(path.Join(wrkDir, netDataFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var b models_storage.NetworkData
	err = json.NewDecoder(f).Decode(&b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b, a) {
		t.Errorf("expected '%v' got '%v'", a, b)
	}
}

func TestHandler_RemoveCertificate(t *testing.T) {
	wrkDir := t.TempDir()
	f, err := os.Create(path.Join(wrkDir, certDataFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = json.NewEncoder(f).Encode(models_storage.CertData{
		ValidityPeriod: time.Second,
		Created:        time.Time{},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := New(wrkDir)
	err = h.Init()
	if err != nil {
		t.Fatal(err)
	}
	err = h.RemoveCertificate(context.Background())
	if err != nil {
		t.Error(err)
	}
	if h.certData != nil {
		t.Error("should be nil")
	}
	_, err = os.Stat(path.Join(wrkDir, certDataFile))
	if err == nil {
		t.Error("expected error")
	}
}

func TestHandler_RemoveNetwork(t *testing.T) {
	wrkDir := t.TempDir()
	nf, err := os.Create(path.Join(wrkDir, netDataFile))
	if err != nil {
		t.Fatal(err)
	}
	defer nf.Close()
	err = json.NewEncoder(nf).Encode(models_storage.NetworkData{
		ID:     "id",
		UserID: "user_id",
		Added:  time.Time{},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := New(wrkDir)
	err = h.Init()
	if err != nil {
		t.Fatal(err)
	}
	err = h.RemoveNetwork(context.Background())
	if err != nil {
		t.Error(err)
	}
	if h.networkData != nil {
		t.Error("should be nil")
	}
	_, err = os.Stat(path.Join(wrkDir, netDataFile))
	if err == nil {
		t.Error("expected error")
	}
}
