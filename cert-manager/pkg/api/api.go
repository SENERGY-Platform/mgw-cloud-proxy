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
	gin_mw "github.com/SENERGY-Platform/gin-middleware"
	"github.com/SENERGY-Platform/go-service-base/struct-logger/attributes"
	models_api "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/api"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/slog_attr"
	"github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
	"log/slog"
)

func init() {
	gin.SetMode(gin.ReleaseMode)
}

type Api struct {
	service   serviceItf
	infoHdl   infoHandler
	ginEngine *gin.Engine
}

// New godoc
// @title Cert-Manager
// @version 0.0.9
// @description Provides network and certificate management functions.
// @license.name Apache-2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @BasePath /
func New(service serviceItf, infoHdl infoHandler, staticHeader map[string]string, logger *slog.Logger, accessLog bool) (*Api, error) {
	ginEngine := gin.New()
	var middleware []gin.HandlerFunc
	if accessLog {
		middleware = append(
			middleware,
			gin_mw.StructLoggerHandler(
				logger.With(attributes.LogRecordTypeKey, attributes.HttpAccessLogRecordTypeVal),
				attributes.Provider,
				nil,
				nil,
				requestIDGenerator,
			),
		)
	}
	middleware = append(middleware,
		gin_mw.StaticHeaderHandler(staticHeader),
		requestid.New(requestid.WithCustomHeaderStrKey(models_api.HeaderRequestID)),
		gin_mw.ErrorHandler(getStatusCode, ", "),
		gin_mw.StructRecoveryHandler(logger, gin_mw.DefaultRecoveryFunc),
	)
	ginEngine.Use(middleware...)
	ginEngine.UseRawPath = true
	a := &Api{
		service:   service,
		infoHdl:   infoHdl,
		ginEngine: ginEngine,
	}
	setRoutes, err := routes.Set(a, ginEngine)
	if err != nil {
		return nil, err
	}
	for _, route := range setRoutes {
		logger.Debug("http route", attributes.MethodKey, route[0], attributes.PathKey, route[1])
	}
	return a, nil
}

func (a *Api) Handler() *gin.Engine {
	return a.ginEngine
}

func requestIDGenerator(gc *gin.Context) (string, any) {
	return slog_attr.RequestIDKey, requestid.Get(gc)
}
