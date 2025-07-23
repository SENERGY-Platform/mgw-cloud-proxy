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
	"fmt"
	"github.com/SENERGY-Platform/go-service-base/struct-logger/attributes"
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/cert"
	models_service "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/service"
	client_cloud "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/components/clients/cloud"
	models_error "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/error"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/slog_attr"
	models_storage "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/storage"
	mm_model "github.com/SENERGY-Platform/mgw-module-manager/lib/model"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

const depAdvRef = "network"
const depIDPlaceholder = "{did}"

type Service struct {
	certHdl         certificateHandler
	storageHdl      storageHandler
	depAdvClt       deploymentAdvertisementsClient
	cloudClt        cloudClient
	subjectFunc     subjectProvider
	nginxReloadFunc nginxReloadHandler
	config          Config
	renewCertTime   time.Time
	mu              sync.RWMutex
}

func New(certHandler certificateHandler, storageHdl storageHandler, depAdvClt deploymentAdvertisementsClient, cloudClt cloudClient, subjectFunc subjectProvider, nginxReloadFunc nginxReloadHandler, config Config) *Service {
	return &Service{
		certHdl:         certHandler,
		storageHdl:      storageHdl,
		depAdvClt:       depAdvClt,
		cloudClt:        cloudClt,
		subjectFunc:     subjectFunc,
		nginxReloadFunc: nginxReloadFunc,
		config:          config,
	}
}

func (s *Service) NetworkInfo(ctx context.Context, cloudStatus bool, token string) (models_service.NetworkInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := s.storageHdl.ReadNetwork(ctx)
	if err != nil {
		return models_service.NetworkInfo{}, err
	}
	var cs models_service.CloudStatus
	if cloudStatus {
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
	}
	return models_service.NetworkInfo{
		ID:          data.ID,
		UserID:      data.UserID,
		Added:       data.Added,
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
		if name == "" {
			name = strings.Replace(s.config.DefaultNetworkName, depIDPlaceholder, s.config.DeploymentID, -1)
		}
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
	err = s.depAdvClt.PutDepAdvertisement(ctx, s.config.DeploymentID, newDepAdvBase(id))
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) RemoveNetwork(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.storageHdl.RemoveNetwork(ctx)
	if err != nil {
		return err
	}
	err = s.depAdvClt.DeleteDepAdvertisement(ctx, s.config.DeploymentID, depAdvRef)
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) AdvertiseNetwork(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := s.storageHdl.ReadNetwork(ctx)
	if err != nil {
		return err
	}
	err = s.depAdvClt.PutDepAdvertisement(ctx, s.config.DeploymentID, newDepAdvBase(data.ID))
	if err != nil {
		return err
	}
	return nil
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
		Info:           certInfo,
		ValidityPeriod: data.ValidityPeriod,
		Created:        data.Created,
		LastChecked:    s.renewCertTime,
	}, nil
}

func (s *Service) NewCertificate(ctx context.Context, dn models_cert.DistinguishedName, validityPeriod time.Duration, userPrivateKey []byte, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	netData, err := s.storageHdl.ReadNetwork(ctx)
	if err != nil {
		return err
	}
	if validityPeriod == 0 {
		validityPeriod = s.config.DefaultCertValidityPeriod
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
	if validityPeriod == 0 {
		validityPeriod = s.config.DefaultCertValidityPeriod
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

func (s *Service) PeriodicCertificateRenewal(ctx context.Context) error {
	logger.Info("starting periodic certificate renewal")
	var lErr error
	defer func() {
		if r := recover(); r != nil {
			lErr = fmt.Errorf("%s", r)
			logger.Error("periodic certificate renewal panicked", slog_attr.StackTraceKey, string(debug.Stack()))
		}
		logger.Info("periodic certificate renewal halted")
	}()
	timer := time.NewTimer(s.config.InitialDelay)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	loop := true
	for loop {
		select {
		case <-timer.C:
			err := s.renewCertificate(ctx)
			if err != nil {
				if !errors.Is(err, models_error.NoCertificateErr) {
					logger.Error("certificate renewal failed", attributes.ErrorKey, err)
				}
			}
			timer.Reset(s.config.CheckInterval)
		case <-ctx.Done():
			loop = false
			logger.Info("stopping periodic certificate renewal")
			break
		}
	}
	return lErr
}

func (s *Service) renewCertificate(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	certInfo, err := s.certHdl.Info(ctx)
	if err != nil {
		return err
	}
	s.renewCertTime = time.Now().UTC()
	if s.renewCertTime.After(certInfo.NotAfter) {
		return models_error.CertificateExpiredErr
	}
	if certInfo.NotAfter.Sub(s.renewCertTime) > certInfo.NotAfter.Sub(certInfo.NotBefore)/2 {
		return nil
	}
	certData, err := s.storageHdl.ReadCertificate(ctx)
	if err != nil {
		return err
	}
	netData, err := s.storageHdl.ReadNetwork(ctx)
	if err != nil {
		return err
	}
	err = s.certHdl.Renew(ctx, certInfo.Subject, []string{netData.ID}, certData.ValidityPeriod, "")
	if err != nil {
		return err
	}
	certData.Created = time.Now().UTC()
	err = s.storageHdl.WriteCertificate(ctx, certData)
	if err != nil {
		return err
	}
	err = s.nginxReloadFunc()
	if err != nil {
		return err
	}
	return nil
}

func newDepAdvBase(id string) mm_model.DepAdvertisementBase {
	return mm_model.DepAdvertisementBase{
		Ref: depAdvRef,
		Items: map[string]string{
			"id": id,
		},
	}
}
