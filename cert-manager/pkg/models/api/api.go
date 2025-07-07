package api

import (
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/cert"
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
