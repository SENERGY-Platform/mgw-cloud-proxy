package api

import (
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/cert"
	"time"
)

const (
	HeaderRequestID = "X-Request-ID"
	HeaderApiVer    = "X-Api-Version"
	HeaderSrvName   = "X-Service-Name"
	HeaderAuth      = "Authorization"
)

type NewNetworkRequest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type NewCertRequest struct {
	models_cert.DistinguishedName
	ValidityPeriod string `json:"validity_period"`
	PrivateKey     string `json:"private_key"`
}

type RenewCertRequest struct {
	models_cert.DistinguishedName
	ValidityPeriod string `json:"validity_period"`
}

type CertInfo struct {
	models_cert.Info
	ValidityPeriod string    `json:"validity_period"`
	Created        time.Time `json:"created"`
	LastChecked    time.Time `json:"last_checked"`
}
