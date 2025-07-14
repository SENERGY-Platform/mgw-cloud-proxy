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
	"errors"
	"github.com/SENERGY-Platform/go-service-base/struct-logger/attributes"
	client_cloud "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/components/clients/cloud"
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/cert"
	models_error "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/error"
	models_service "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/service"
	models_storage "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/storage"
	"net/http"
	"sync"
	"time"
)

type Service struct {
	certHdl         certificateHandler
	storageHdl      storageHandler
	cloudClt        cloudClient
	subjectFunc     subjectProvider
	nginxReloadFunc nginxReloadHandler
	lastCertCheck   time.Time
	mu              sync.RWMutex
	serviceInfoHandler
}

func New(certHandler certificateHandler, storageHdl storageHandler, cloudClt cloudClient, subjectFunc subjectProvider, nginxReloadFunc nginxReloadHandler, srvInfoHdl serviceInfoHandler) *Service {
	return &Service{
		certHdl:            certHandler,
		storageHdl:         storageHdl,
		cloudClt:           cloudClt,
		subjectFunc:        subjectFunc,
		nginxReloadFunc:    nginxReloadFunc,
		serviceInfoHandler: srvInfoHdl,
	}
}

func (s *Service) NetworkInfo(ctx context.Context, token string) (models_service.NetworkInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := s.storageHdl.ReadNetwork(ctx)
	if err != nil {
		return models_service.NetworkInfo{}, err
	}
	var cs models_service.CloudStatus
	_, err = s.cloudClt.GetNetwork(ctx, data.ID, token)
	if err != nil {
		logger.Error("getting network failed", attributes.ErrorKey, err)
		cs.Error = err.Error()
		var rErr *client_cloud.ResponseError
		if errors.As(err, &rErr) {
			cs.Code = rErr.Code
		}
	} else {
		cs.Code = http.StatusOK
	}
	return models_service.NetworkInfo{
		NetworkData: data,
		CloudStatus: cs,
	}, nil
}

func (s *Service) NewNetwork(ctx context.Context, id, name, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, err := s.subjectFunc(token)
	if err != nil {
		return err
	}
	if id != "" {
		n, err := s.cloudClt.GetNetwork(ctx, id, token)
		if err != nil {
			return err
		}
		if n.OwnerID != userID {
			return models_error.NetworkIDErr
		}
	} else {
		newID, err := s.cloudClt.CreateNetwork(ctx, name, token)
		if err != nil {
			return err
		}
		id = newID
	}
	err = s.storageHdl.WriteNetwork(ctx, models_storage.NetworkData{
		ID:     id,
		UserID: userID,
		Added:  time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) RemoveNetwork(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.storageHdl.RemoveNetwork(ctx)
}

func (s *Service) CertificateInfo(ctx context.Context) (models_service.CertInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	certInfo, err := s.certHdl.Info(ctx)
	if err != nil {
		return models_service.CertInfo{}, err
	}
	data, err := s.storageHdl.ReadCertificate(ctx)
	if err != nil {
		logger.Error("reading certificate data failed", attributes.ErrorKey, err)
	}
	return models_service.CertInfo{
		Info:        certInfo,
		CertData:    data,
		LastChecked: s.lastCertCheck,
	}, nil
}

func (s *Service) NewCertificate(ctx context.Context, dn models_cert.DistinguishedName, validityPeriod time.Duration, userPrivateKey []byte, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	netData, err := s.storageHdl.ReadNetwork(ctx)
	if err != nil {
		return err
	}
	err = s.certHdl.New(ctx, dn, []string{netData.ID}, validityPeriod, userPrivateKey, token)
	if err != nil {
		return err
	}
	err = s.storageHdl.WriteCertificate(ctx, models_storage.CertData{
		ValidityPeriod: validityPeriod,
		Created:        time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	err = s.nginxReloadFunc()
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) RenewCertificate(ctx context.Context, dn models_cert.DistinguishedName, validityPeriod time.Duration, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	netData, err := s.storageHdl.ReadNetwork(ctx)
	if err != nil {
		return err
	}
	err = s.certHdl.Renew(ctx, dn, []string{netData.ID}, validityPeriod, token)
	if err != nil {
		return err
	}
	err = s.storageHdl.WriteCertificate(ctx, models_storage.CertData{
		ValidityPeriod: validityPeriod,
		Created:        time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	err = s.nginxReloadFunc()
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) RemoveCertificate(ctx context.Context, reason, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.certHdl.Clear(ctx, reason, token)
	if err != nil {
		return err
	}
	err = s.storageHdl.RemoveCertificate(ctx)
	if err != nil {
		return err
	}
	err = s.nginxReloadFunc()
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) DeployCertificate(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.certHdl.Deploy(ctx)
	if err != nil {
		return err
	}
	err = s.nginxReloadFunc()
	if err != nil {
		return err
	}
	return nil
}
