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

package service

import (
	"context"
	"github.com/SENERGY-Platform/go-service-base/srv-info-hdl"
	client_cloud "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/clients/cloud"
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/cert"
	models_storage "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/storage"
	"time"
)

type certificateHandler interface {
	Info(ctx context.Context) (models_cert.Info, error)
	New(ctx context.Context, dn models_cert.DistinguishedName, subAltNames []string, validityPeriod time.Duration, userPrivateKey []byte, token string) error
	Renew(ctx context.Context, dn models_cert.DistinguishedName, subAltNames []string, validityPeriod time.Duration, token string) error
	Clear(ctx context.Context, reason, token string) error
	Deploy(ctx context.Context) error
}

type storageHandler interface {
	ReadCertificate(ctx context.Context) (models_storage.CertData, error)
	ReadNetwork(ctx context.Context) (models_storage.NetworkData, error)
	WriteCertificate(ctx context.Context, data models_storage.CertData) error
	WriteNetwork(ctx context.Context, data models_storage.NetworkData) error
	RemoveCertificate(ctx context.Context) error
	RemoveNetwork(ctx context.Context) error
}

type cloudClient interface {
	CreateNetwork(ctx context.Context, name, token string) (string, error)
	GetNetwork(ctx context.Context, id, token string) (client_cloud.Network, error)
}

type serviceInfoHandler interface {
	ServiceInfo() srv_info_hdl.ServiceInfo
}

type subjectProvider func(token string) (string, error)

type nginxReloadHandler func() error
