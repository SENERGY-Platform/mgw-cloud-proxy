package service

import (
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/cert"
	models_storage "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/storage"
	"time"
)

type CertInfo struct {
	models_cert.Info
	models_storage.CertData
	LastChecked time.Time `json:"last_checked"`
}

type NetworkInfo struct {
	models_storage.NetworkData
	CloudStatus CloudStatus `json:"cloud_status"`
}

type CloudStatus struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
}
