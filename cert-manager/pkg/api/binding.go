package api

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin/binding"
	"io"
	"net/http"
)

var DecoderUseNumber = false
var DecoderDisallowUnknownFields = false

type jsonBinding struct{}

func (jsonBinding) Name() string {
	return "json"
}

func (jsonBinding) Bind(req *http.Request, obj any) error {
	return decodeJSON(req.Body, obj)
}

func (jsonBinding) BindBody(body []byte, obj any) error {
	return decodeJSON(bytes.NewReader(body), obj)
}

func decodeJSON(r io.Reader, obj any) error {
	buffer := bytes.NewBuffer(nil)
	n, err := io.Copy(buffer, r)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	decoder := json.NewDecoder(buffer)
	if DecoderUseNumber {
		decoder.UseNumber()
	}
	if DecoderDisallowUnknownFields {
		decoder.DisallowUnknownFields()
	}
	if err = decoder.Decode(obj); err != nil {
		return err
	}
	if binding.Validator == nil {
		return nil
	}
	return binding.Validator.ValidateStruct(obj)
}
