package cloud

import (
	"net/http"
)

type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (r *ResponseError) Error() string {
	return r.Message
}

func NewResponseError(c int, b []byte) *ResponseError {
	var msg string
	if len(b) == 0 {
		msg = http.StatusText(c)
	} else {
		msg = string(b)
	}
	return &ResponseError{
		Code:    c,
		Message: msg,
	}
}
