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

package error

import "errors"

var NoCertificateErr = errors.New("no certificate")
var NoCertificateDataErr = errors.New("no certificate data")
var NoNetworkDataErr = errors.New("no network data")
var NetworkIDErr = errors.New("user ID does not match network owner ID")
var CertificateExpiredErr = errors.New("certificate expired")

func NewInputErr(e error) *InputErr {
	return &InputErr{err: e}
}

type InputErr struct {
	err error
}

func (e *InputErr) Error() string {
	return e.err.Error()
}

func (e *InputErr) Unwrap() error {
	return e.err
}

func (e *InputErr) Is(err error) bool {
	_, ok := err.(*InputErr)
	return ok
}
