package service

import (
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/cert"
	"time"
)

type CertInfo struct {
	models_cert.Info
	ValidityPeriod time.Duration `json:"validity_period"`
	Created        time.Time     `json:"created"`
	LastChecked    time.Time     `json:"last_checked"`
}

type NetworkInfo struct {
	ID          string      `json:"id"`
	UserID      string      `json:"user_id"`
	Added       time.Time   `json:"added"`
	CloudStatus CloudStatus `json:"cloud_status"`
}

type CloudStatus struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
}
