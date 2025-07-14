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
	"encoding/base64"
	_ "github.com/SENERGY-Platform/go-service-base/srv-info-hdl"
	models_api "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/api"
	models_error "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/error"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func getNetworkInfo(srv service) (string, string, gin.HandlerFunc) {
	return http.MethodGet, "/network", func(gc *gin.Context) {
		info, err := srv.NetworkInfo(gc.Request.Context(), gc.GetHeader(models_api.HeaderAuth))
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.JSON(http.StatusOK, info)
	}
}

func postNewNetwork(srv service) (string, string, gin.HandlerFunc) {
	return http.MethodPost, "/network", func(gc *gin.Context) {
		var req models_api.NewNetworkRequest
		err := gc.ShouldBindJSON(&req)
		if err != nil {
			_ = gc.Error(models_error.NewInputErr(err))
			return
		}
		err = srv.NewNetwork(gc.Request.Context(), req.ID, req.Name, gc.GetHeader(models_api.HeaderAuth))
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Status(http.StatusOK)
	}
}

func deleteRemoveNetwork(srv service) (string, string, gin.HandlerFunc) {
	return http.MethodDelete, "/network", func(gc *gin.Context) {
		err := srv.RemoveNetwork(gc.Request.Context())
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Status(http.StatusOK)
	}
}

func getCertificateInfo(srv service) (string, string, gin.HandlerFunc) {
	return http.MethodGet, "/certificate", func(gc *gin.Context) {
		info, err := srv.CertificateInfo(gc.Request.Context())
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.JSON(http.StatusOK, models_api.CertInfo{
			Info:           info.Info,
			ValidityPeriod: info.ValidityPeriod.String(),
			Created:        info.Created,
			LastChecked:    info.LastChecked,
		})
	}
}

func postNewCertificate(srv service) (string, string, gin.HandlerFunc) {
	return http.MethodPost, "/certificate", func(gc *gin.Context) {
		var req models_api.NewCertRequest
		err := gc.ShouldBindJSON(&req)
		if err != nil {
			_ = gc.Error(models_error.NewInputErr(err))
			return
		}
		var keyBytes []byte
		if req.PrivateKey != "" {
			keyBytes, err = base64.StdEncoding.DecodeString(req.PrivateKey)
			if err != nil {
				_ = gc.Error(models_error.NewInputErr(err))
				return
			}
		}
		var validityPeriod time.Duration
		if req.ValidityPeriod != "" {
			validityPeriod, err = time.ParseDuration(req.ValidityPeriod)
			if err != nil {
				_ = gc.Error(models_error.NewInputErr(err))
				return
			}
		}
		err = srv.NewCertificate(gc.Request.Context(), req.DistinguishedName, validityPeriod, keyBytes, gc.GetHeader(models_api.HeaderAuth))
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Status(http.StatusOK)
	}
}

func patchRenewCertificate(srv service) (string, string, gin.HandlerFunc) {
	return http.MethodPatch, "/certificate", func(gc *gin.Context) {
		var req models_api.RenewCertRequest
		err := gc.ShouldBindJSON(&req)
		if err != nil {
			_ = gc.Error(models_error.NewInputErr(err))
			return
		}
		var validityPeriod time.Duration
		if req.ValidityPeriod != "" {
			validityPeriod, err = time.ParseDuration(req.ValidityPeriod)
			if err != nil {
				_ = gc.Error(models_error.NewInputErr(err))
				return
			}
		}
		err = srv.RenewCertificate(gc.Request.Context(), req.DistinguishedName, validityPeriod, gc.GetHeader(models_api.HeaderAuth))
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Status(http.StatusOK)
	}
}

func deleteRemoveCertificate(srv service) (string, string, gin.HandlerFunc) {
	return http.MethodDelete, "/certificate", func(gc *gin.Context) {
		err := srv.RemoveCertificate(gc.Request.Context(), gc.Query("reason"), gc.GetHeader(models_api.HeaderAuth))
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Status(http.StatusOK)
	}
}

func patchDeployCertificate(srv service) (string, string, gin.HandlerFunc) {
	return http.MethodPatch, "/certificate/deploy", func(gc *gin.Context) {
		err := srv.DeployCertificate(gc.Request.Context())
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Status(http.StatusOK)
	}
}

func getInfoH(srv service) (string, string, gin.HandlerFunc) {
	return http.MethodGet, "/info", func(gc *gin.Context) {
		gc.JSON(http.StatusOK, srv.ServiceInfo())
	}
}
