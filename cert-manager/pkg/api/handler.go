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
	_ "github.com/SENERGY-Platform/mgw-cloud-proxy/pkg/models/service"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"time"
)

// getNetworkInfo godoc
// @Summary Info
// @Description Get info like ID, user ID and cloud status of the stored network.
// @Tags Network
// @Produce	json
// @Param Authorization header string false "jwt token"
// @Success	200 {object} service.NetworkInfo ""
// @Failure	404 {string} string "error message"
// @Failure	500 {string} string "error message"
// @Router /network [get]
func getNetworkInfo(srv Service) (string, string, gin.HandlerFunc) {
	return http.MethodGet, "/network", func(gc *gin.Context) {
		info, err := srv.NetworkInfo(gc.Request.Context(), gc.GetHeader(models_api.HeaderAuth))
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.JSON(http.StatusOK, info)
	}
}

// postNewNetwork godoc
// @Summary New
// @Description Add an existing network or create a new network.
// @Tags Network
// @Accept json
// @Param Authorization header string false "jwt token"
// @Param data body models_api.NewNetworkRequest true "network data"
// @Success	200
// @Failure	400 {string} string "error message"
// @Failure	500 {string} string "error message"
// @Router /network [post]
func postNewNetwork(srv Service) (string, string, gin.HandlerFunc) {
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

// deleteRemoveNetwork godoc
// @Summary Remove
// @Description Remove the stored network.
// @Tags Network
// @Success	200
// @Failure	404 {string} string "error message"
// @Failure	500 {string} string "error message"
// @Router /network [delete]
func deleteRemoveNetwork(srv Service) (string, string, gin.HandlerFunc) {
	return http.MethodDelete, "/network", func(gc *gin.Context) {
		err := srv.RemoveNetwork(gc.Request.Context())
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Status(http.StatusOK)
	}
}

// patchAdvertiseNetwork godoc
// @Summary Advertise
// @Description Advertise the stored network.
// @Tags Network
// @Success	200
// @Failure	404 {string} string "error message"
// @Failure	500 {string} string "error message"
// @Router /network/advertise [patch]
func patchAdvertiseNetwork(srv Service) (string, string, gin.HandlerFunc) {
	return http.MethodPatch, "/network/advertise", func(gc *gin.Context) {
		err := srv.AdvertiseNetwork(gc.Request.Context())
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Status(http.StatusOK)
	}
}

// getCertificateInfo godoc
// @Summary Info
// @Description Get summarized information of the stored certificate.
// @Tags Certificate
// @Produce	json
// @Success	200 {object} service.CertInfo "certificate info"
// @Failure	404 {string} string "error message"
// @Failure	500 {string} string "error message"
// @Router /certificate [get]
func getCertificateInfo(srv Service) (string, string, gin.HandlerFunc) {
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

// postNewCertificate godoc
// @Summary New
// @Description Create a new certificate and deploy to nginx. Optional private key must be in PEM format and base64 encoded.
// @Tags Certificate
// @Accept json
// @Param Authorization header string false "jwt token"
// @Param data body models_api.NewCertRequest true "cert data"
// @Success	200
// @Failure	400 {string} string "error message"
// @Failure	500 {string} string "error message"
// @Router /certificate [post]
func postNewCertificate(srv Service) (string, string, gin.HandlerFunc) {
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

// patchRenewCertificate godoc
// @Summary Renew
// @Description Renew the stored certificate and deploy to nginx.
// @Tags Certificate
// @Accept json
// @Param Authorization header string false "jwt token"
// @Param data body models_api.RenewCertRequest true "cert data"
// @Success	200
// @Failure	400 {string} string "error message"
// @Failure	404 {string} string "error message"
// @Failure	500 {string} string "error message"
// @Router /certificate [patch]
func patchRenewCertificate(srv Service) (string, string, gin.HandlerFunc) {
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

// deleteRemoveCertificate godoc
// @Summary Remove
// @Description Remove and revoke the stored certificate.
// @Tags Certificate
// @Param Authorization header string false "jwt token"
// @Param reason query string false "revokation reason"
// @Success	200
// @Failure	404 {string} string "error message"
// @Failure	500 {string} string "error message"
// @Router /certificate [delete]
func deleteRemoveCertificate(srv Service) (string, string, gin.HandlerFunc) {
	return http.MethodDelete, "/certificate", func(gc *gin.Context) {
		err := srv.RemoveCertificate(gc.Request.Context(), gc.Query("reason"), gc.GetHeader(models_api.HeaderAuth))
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Status(http.StatusOK)
	}
}

// patchDeployCertificate godoc
// @Summary Deploy
// @Description Deploy stored certificate to nginx.
// @Tags Certificate
// @Success	200
// @Failure	404 {string} string "error message"
// @Failure	500 {string} string "error message"
// @Router /certificate/deploy [patch]
func patchDeployCertificate(srv Service) (string, string, gin.HandlerFunc) {
	return http.MethodPatch, "/certificate/deploy", func(gc *gin.Context) {
		err := srv.DeployCertificate(gc.Request.Context())
		if err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Status(http.StatusOK)
	}
}

// getInfoH godoc
// @Summary Info
// @Description Get service information like version, uptime and memory usage.
// @Tags Info
// @Produce	json
// @Success	200 {object} srv_info_hdl.ServiceInfo "service info"
// @Failure	500 {string} string "error message"
// @Router /info [get]
func getInfoH(srv Service) (string, string, gin.HandlerFunc) {
	return http.MethodGet, "/info", func(gc *gin.Context) {
		gc.JSON(http.StatusOK, srv.ServiceInfo())
	}
}

func getSwagger(_ Service) (string, string, gin.HandlerFunc) {
	return http.MethodGet, "/swagger", func(gc *gin.Context) {
		if _, err := os.Stat("/opt/cert-manager/docs/swagger.json"); err != nil {
			_ = gc.Error(err)
			return
		}
		gc.Header("Content-Type", gin.MIMEJSON)
		gc.File("/opt/cert-manager/docs/swagger.json")
	}
}
