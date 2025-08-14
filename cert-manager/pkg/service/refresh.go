package service

import (
	"context"
	"errors"
	"github.com/SENERGY-Platform/go-service-base/struct-logger/attributes"
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/cert"
	client_cloud "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/components/clients/cloud"
	models_error "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/error"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/slog_attr"
	"net/http"
	"strings"
	"time"
)

func (s *Service) RefreshNetworkAndCertificate(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	netID, err := s.refreshNetwork(ctx, token)
	if err != nil {
		return err
	}
	return s.refreshCertificate(ctx, token, netID)
}

func (s *Service) refreshNetwork(ctx context.Context, token string) (string, error) {
	var ids []string
	data, err := s.storageHdl.ReadNetwork(ctx)
	if err != nil && !errors.Is(err, models_error.NoNetworkDataErr) {
		return "", err
	}
	userID, err := s.subjectFunc(token)
	if err != nil {
		return "", err
	}
	var id string
	for _, tmpID := range append(ids, data.ID, s.config.DefaultNetworkID) {
		if tmpID == "" {
			continue
		}
		n, err := s.cloudClt.GetNetwork(ctx, tmpID, token)
		if err != nil {
			var rErr *client_cloud.ResponseError
			if errors.As(err, &rErr) && rErr.Code == http.StatusNotFound {
				logger.Error("getting network failed", slog_attr.IDKey, tmpID, attributes.ErrorKey, err)
				continue
			}
			return "", err
		}
		if n.OwnerID != userID {
			logger.Error("invalid network", slog_attr.IDKey, tmpID, attributes.ErrorKey, models_error.NetworkIDErr)
			continue
		}
		id = tmpID
	}
	if id == "" {
		tmpID, err := s.cloudClt.CreateNetwork(ctx, strings.Replace(s.config.DefaultNetworkName, depIDPlaceholder, s.config.DeploymentID, -1), token)
		if err != nil {
			return "", err
		}
		id = tmpID
	}
	if data.ID != id || data.UserID != userID {
		if data.ID != id {
			data.Added = time.Now().UTC()
		}
		data.ID = id
		data.UserID = userID
		err = s.storageHdl.WriteNetwork(ctx, data)
		if err != nil {
			return "", err
		}
		err = s.depAdvClt.PutDepAdvertisement(ctx, s.config.DeploymentID, newDepAdvBase(id))
		if err != nil {
			if s.config.DeveloperMode {
				logger.Error("publishing network advertisement failed", attributes.ErrorKey, err)
				return id, nil
			}
			return "", err
		}
	}
	return id, nil
}

func (s *Service) refreshCertificate(ctx context.Context, token, netID string) error {
	data, err := s.storageHdl.ReadCertificate(ctx)
	if err != nil && !errors.Is(err, models_error.NoCertificateDataErr) {
		return err
	}
	hasCert := true
	_, err = s.certHdl.Info(ctx)
	if err != nil {
		if !errors.Is(err, models_error.NoCertificateErr) {
			return err
		}
		hasCert = false
	}
	if data.ValidityPeriod == 0 {
		data.ValidityPeriod = s.config.DefaultCertValidityPeriod
	}
	if hasCert {
		err = s.certHdl.Renew(ctx, models_cert.DistinguishedName{}, []string{netID}, data.ValidityPeriod, token)
		if err != nil {
			return err
		}
	} else {
		err = s.certHdl.New(ctx, models_cert.DistinguishedName{}, []string{netID}, data.ValidityPeriod, nil, token)
		if err != nil {
			return err
		}
	}
	data.Created = time.Now().UTC()
	err = s.storageHdl.WriteCertificate(ctx, data)
	if err != nil {
		return err
	}
	err = s.nginxReloadFunc()
	if err != nil {
		return err
	}
	return nil
}
