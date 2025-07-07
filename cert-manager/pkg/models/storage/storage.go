package storage

import "time"

type CertData struct {
	ValidityPeriod time.Duration `json:"validity_period"`
	Created        time.Time     `json:"created"`
}

type NetworkData struct {
	ID      string    `json:"id"`
	UserID  string    `json:"user_id"`
	Created time.Time `json:"created"`
}
