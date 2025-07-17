package cert

import "time"

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

type Info struct {
	Version            int               `json:"version"`
	SerialNumber       string            `json:"serial_number"`
	NotBefore          time.Time         `json:"not_before"`
	NotAfter           time.Time         `json:"not_after"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm"`
	Issuer             DistinguishedName `json:"issuer"`
	Subject            DistinguishedName `json:"subject"`
	SubjectAltNames    SANs              `json:"subject_alt_names"`
}

type SANs struct {
	DNSNames       []string `json:"dns_names"`
	EmailAddresses []string `json:"email_addresses"`
	IPAddresses    []string `json:"ip_addresses"`
	URIs           []string `json:"uris"`
}

type DistinguishedName struct {
	Country            []string `json:"country"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Locality           []string `json:"locality"`
	Province           []string `json:"province"`
	StreetAddress      []string `json:"street_address"`
	PostalCode         []string `json:"postal_code"`
	SerialNumber       string   `json:"serial_number"`
	CommonName         string   `json:"common_name"`
}
