package service

import "time"

type Config struct {
	DefaultCertValidityPeriod time.Duration `json:"default_cert_validity_period" env_var:"DEFAULT_CERT_VALIDITY_PERIOD"`
	DefaultNetworkName        string        `json:"default_network_name" env_var:"DEFAULT_NETWORK_NAME"`
	DeploymentID              string        `json:"deployment_id" env_var:"MGW_DID"`
	InitialDelay              time.Duration `json:"initial_delay" env_var:"INITIAL_DELAY"`
	CheckInterval             time.Duration `json:"check_interval" env_var:"CHECK_INTERVAL"`
}
