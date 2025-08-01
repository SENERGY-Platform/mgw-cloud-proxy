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
	"errors"
	models_error "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/pkg/models/error"
	"net/http"
)

var errMap = map[error]int{
	models_error.NewInputErr(nil):     http.StatusBadRequest,
	models_error.NetworkIDErr:         http.StatusForbidden,
	models_error.NoCertificateErr:     http.StatusNotFound,
	models_error.NoCertificateDataErr: http.StatusNotFound,
	models_error.NoNetworkDataErr:     http.StatusNotFound,
}

func getStatusCode(err error) int {
	for e, c := range errMap {
		if errors.Is(err, e) {
			return c
		}
	}
	return 0
}
