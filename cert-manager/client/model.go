package client

import (
	srv_info_hdl "github.com/SENERGY-Platform/go-service-base/srv-info-hdl"
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/cert"
	models_service "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/service"
)

const (
	CRLReasonUnspecified          = "unspecified"
	CRLReasonKeyCompromise        = "keyCompromise"
	CRLReasonCACompromise         = "cACompromise"
	CRLReasonAffiliationChanged   = "affiliationChanged"
	CRLReasonSuperseded           = "superseded"
	CRLReasonCessationOfOperation = "cessationOfOperation"
	CRLReasonCertificateHold      = "certificateHold"
	CRLReasonRemoveFromCRL        = "removeFromCRL"
	CRLReasonPrivilegeWithdrawn   = "privilegeWithdrawn"
	CRLReasonAACompromise         = "aACompromise"
)

type NetworkInfo = models_service.NetworkInfo
type CertInfo = models_service.CertInfo
type DistinguishedName = models_cert.DistinguishedName
type ServiceInfo = srv_info_hdl.ServiceInfo
