/*
 * Copyright 2025 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package api

import (
	"context"
	srv_info_hdl "github.com/SENERGY-Platform/go-service-base/srv-info-hdl"
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/cert"
	models_service "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/service"
	"time"
)

type serviceItf interface {
	NetworkInfo(ctx context.Context, token string) (models_service.NetworkInfo, error)
	NewNetwork(ctx context.Context, id, name, token string) error
	RemoveNetwork(ctx context.Context) error
	AdvertiseNetwork(ctx context.Context) error
	CertificateInfo(ctx context.Context) (models_service.CertInfo, error)
	NewCertificate(ctx context.Context, dn models_cert.DistinguishedName, validityPeriod time.Duration, userPrivateKey []byte, token string) error
	RenewCertificate(ctx context.Context, dn models_cert.DistinguishedName, validityPeriod time.Duration, token string) error
	RemoveCertificate(ctx context.Context, reason, token string) error
	DeployCertificate(ctx context.Context) error
}

type infoHandler interface {
	ServiceInfo() srv_info_hdl.ServiceInfo
}
