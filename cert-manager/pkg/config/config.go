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
	"io/fs"
	"os"
	"time"
)

type SocketConfig struct {
	Path     string      `json:"path" env_var:"SOCKET_PATH"`
	GroupID  int         `json:"group_id" env_var:"SOCKET_GROUP_ID"`
	FileMode fs.FileMode `json:"file_mode" env_var:"SOCKET_FILE_MODE"`
}

type Config struct {
	PidFilePath   string               `json:"pid_file_path" env_var:"PID_FILE_PATH"`
	WorkDirPath   string               `json:"work_dir_path" env_var:"WORK_DIR_PATH"`
	Socket        SocketConfig         `json:"socket"`
	Logger        struct_logger.Config `json:"logger"`
	HttpAccessLog bool                 `json:"http_access_log" env_var:"HTTP_ACCESS_LOG"`
}

func New(path string) (*Config, error) {
	cfg := Config{
		PidFilePath: "./cert_manager.pid",
		WorkDirPath: "./data",
		Socket: SocketConfig{
			Path:     "./cert_manager.sock",
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
	}
	err := sb_config_hdl.Load(&cfg, nil, envTypeParser, nil, path)
	return &cfg, err
}
