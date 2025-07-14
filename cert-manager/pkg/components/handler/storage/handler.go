package storage

import (
	"context"
	"encoding/json"
	"errors"
	helper_file "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/helper/file"
	models_error "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/error"
	models_storage "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/storage"
	"os"
	"path"
	"sync"
)

const (
	certDataFile = "cert_data.json"
	netDataFile  = "net_data.json"
)

type Handler struct {
	workDirPath string
	mu          sync.RWMutex
}

func New(workDirPath string) *Handler {
	return &Handler{workDirPath: workDirPath}
}

func (h *Handler) Init() error {
	return os.MkdirAll(h.workDirPath, 0666)
}

func (h *Handler) ReadCertificate(_ context.Context) (models_storage.CertData, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var data models_storage.CertData
	if err := read(path.Join(h.workDirPath, certDataFile), &data); err != nil {
		if os.IsNotExist(err) {
			return models_storage.CertData{}, models_error.NoCertificateDataErr
		}
		return models_storage.CertData{}, err
	}
	return data, nil
}

func (h *Handler) ReadNetwork(_ context.Context) (models_storage.NetworkData, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var data models_storage.NetworkData
	if err := read(path.Join(h.workDirPath, netDataFile), &data); err != nil {
		if os.IsNotExist(err) {
			return models_storage.NetworkData{}, models_error.NoNetworkDataErr
		}
		return models_storage.NetworkData{}, err
	}
	return data, nil
}

func (h *Handler) WriteCertificate(_ context.Context, data models_storage.CertData) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := write(path.Join(h.workDirPath, certDataFile), data); err != nil {
		return err
	}
	return nil
}

func (h *Handler) WriteNetwork(_ context.Context, data models_storage.NetworkData) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := write(path.Join(h.workDirPath, netDataFile), data); err != nil {
		return err
	}
	return nil
}

func (h *Handler) RemoveCertificate(_ context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	err := os.Remove(path.Join(h.workDirPath, certDataFile))
	if err != nil {
		if os.IsNotExist(err) {
			return models_error.NoCertificateDataErr
		}
		return err
	}
	return nil
}

func (h *Handler) RemoveNetwork(_ context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	err := os.Remove(path.Join(h.workDirPath, netDataFile))
	if err != nil {
		if os.IsNotExist(err) {
			return models_error.NoNetworkDataErr
		}
		return err
	}
	return nil
}

func read(filePath string, data any) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = json.NewDecoder(file).Decode(data); err != nil {
		return err
	}
	return nil
}

func write(filePath string, data any) error {
	fileBkPath, err := helper_file.BackupFile(filePath, 0664)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
	if err != nil {
		return err
	}
	defer func() {
		file.Close()
		if err != nil && fileBkPath != "" {
			if e := helper_file.Copy(fileBkPath, filePath, 0664); e != nil {
				err = errors.Join(err, e)
			}
		}
	}()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "\t")
	if err = encoder.Encode(data); err != nil {
		return err
	}
	return nil
}
