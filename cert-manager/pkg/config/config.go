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

package config

import (
	sb_config_hdl "github.com/SENERGY-Platform/go-service-base/config-hdl"
	"github.com/SENERGY-Platform/go-service-base/struct-logger"
	handler_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/components/handler/cert"
	helper_listener "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/components/helper/listener"
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/cert"
	"github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/service"
	"os"
	"time"
)

type CloudConfig struct {
	TokenBaseUrl string        `json:"token_base_url" env_var:"CLOUD_TOKEN_BASE_URL"`
	CertBaseUrl  string        `json:"cert_base_url" env_var:"CLOUD_CERT_BASE_URL"`
	HttpTimeout  time.Duration `json:"http_timeout" env_var:"CLOUD_HTTP_TIMEOUT"`
}

type DepAdvConfig struct {
	ModuleManagerBaseUrl string        `json:"module_manager_base_url" env_var:"MODULE_MANAGER_BASE_URL"`
	HttpTimeout          time.Duration `json:"http_timeout" env_var:"DEP_ADV_HTTP_TIMEOUT"`
}

type Config struct {
	PidFilePath   string                 `json:"pid_file_path" env_var:"PID_FILE_PATH"`
	StoragePath   string                 `json:"storage_path" env_var:"STORAGE_PATH"`
	Socket        helper_listener.Config `json:"socket"`
	Logger        struct_logger.Config   `json:"logger"`
	CertHdl       handler_cert.Config    `json:"cert_hdl"`
	Cloud         CloudConfig            `json:"cloud"`
	Service       service.Config         `json:"service"`
	DepAdv        DepAdvConfig           `json:"dep_adv"`
	HttpAccessLog bool                   `json:"http_access_log" env_var:"HTTP_ACCESS_LOG"`
}

func New(path string) (*Config, error) {
	cfg := Config{
		PidFilePath: "/var/run/cert_manager.pid",
		StoragePath: "/opt/cert-manager/data/storage",
		Socket: helper_listener.Config{
			Path:     "/var/run/cert_manager.sock",
			UserID:   os.Getuid(),
			GroupID:  os.Getgid(),
			FileMode: 0660,
		},
		Logger: struct_logger.Config{
			Handler:    struct_logger.TextHandlerSelector,
			Level:      struct_logger.LevelInfo,
			TimeFormat: time.RFC3339Nano,
			TimeUtc:    true,
			AddMeta:    true,
		},
		CertHdl: handler_cert.Config{
			WorkDirPath:         "/opt/cert-manager/data/certs",
			TargetDirPath:       "/opt/certs",
			DummyDirPath:        "/opt/dummy-certs",
			PrivateKeyAlgorithm: models_cert.AlgoRSA,
		},
		Cloud: CloudConfig{
			HttpTimeout: time.Minute,
		},
		DepAdv: DepAdvConfig{
			HttpTimeout: time.Second * 30,
		},
		Service: service.Config{
			DefaultCertValidityPeriod: time.Hour * 2160,
			InitialDelay:              time.Second * 30,
			CheckInterval:             time.Minute * 30,
		},
	}
	err := sb_config_hdl.Load(&cfg, nil, envTypeParser, nil, path)
	return &cfg, err
}
