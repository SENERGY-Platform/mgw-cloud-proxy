package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	models_api "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/api"
	models_cert "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/cert"
	models_service "github.com/SENERGY-Platform/mgw-cloud-proxy/cert-manager/lib/models/service"
	"io"
	"net/http"
	"net/url"
	"time"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	client  HTTPClient
	baseUrl string
}

func New(httpClient HTTPClient, baseUrl string) *Client {
	return &Client{
		client:  httpClient,
		baseUrl: baseUrl,
	}
}

func (c *Client) NetworkInfo(ctx context.Context, cloudStatus bool, token string) (models_service.NetworkInfo, error) {
	u, err := url.JoinPath(c.baseUrl, "network")
	if err != nil {
		return models_service.NetworkInfo{}, err
	}
	if cloudStatus {
		u += "?cloud_status=true"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return models_service.NetworkInfo{}, err
	}
	if token != "" {
		req.Header.Set(models_api.HeaderAuth, token)
	}
	var info models_service.NetworkInfo
	if err = c.doJson(req, &info); err != nil {
		return models_service.NetworkInfo{}, err
	}
	return info, nil
}

func (c *Client) NewNetwork(ctx context.Context, id, name, token string) error {
	u, err := url.JoinPath(c.baseUrl, "network")
	if err != nil {
		return err
	}
	buffer := bytes.NewBuffer(nil)
	err = json.NewEncoder(buffer).Encode(models_api.NewNetworkRequest{
		ID:   id,
		Name: name,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, buffer)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set(models_api.HeaderAuth, token)
	}
	return c.doErr(req)
}

func (c *Client) RemoveNetwork(ctx context.Context) error {
	u, err := url.JoinPath(c.baseUrl, "network")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	return c.doErr(req)
}

func (c *Client) AdvertiseNetwork(ctx context.Context) error {
	u, err := url.JoinPath(c.baseUrl, "network/advertise")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, nil)
	if err != nil {
		return err
	}
	return c.doErr(req)
}

func (c *Client) CertificateInfo(ctx context.Context) (models_service.CertInfo, error) {
	u, err := url.JoinPath(c.baseUrl, "certificate")
	if err != nil {
		return models_service.CertInfo{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return models_service.CertInfo{}, err
	}
	var info models_service.CertInfo
	if err = c.doJson(req, &info); err != nil {
		return models_service.CertInfo{}, err
	}
	return info, nil
}

func (c *Client) NewCertificate(ctx context.Context, dn models_cert.DistinguishedName, validityPeriod time.Duration, userPrivateKey []byte, token string) error {
	u, err := url.JoinPath(c.baseUrl, "certificate")
	if err != nil {
		return err
	}
	var keyString string
	if len(userPrivateKey) > 0 {
		keyString = base64.StdEncoding.EncodeToString(userPrivateKey)
	}
	buffer := bytes.NewBuffer(nil)
	err = json.NewEncoder(buffer).Encode(models_api.NewCertRequest{
		DistinguishedName: dn,
		ValidityPeriod:    validityPeriod.String(),
		PrivateKey:        keyString,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, buffer)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set(models_api.HeaderAuth, token)
	}
	return c.doErr(req)
}

func (c *Client) RenewCertificate(ctx context.Context, dn models_cert.DistinguishedName, validityPeriod time.Duration, token string) error {
	u, err := url.JoinPath(c.baseUrl, "certificate")
	if err != nil {
		return err
	}
	buffer := bytes.NewBuffer(nil)
	err = json.NewEncoder(buffer).Encode(models_api.RenewCertRequest{
		DistinguishedName: dn,
		ValidityPeriod:    validityPeriod.String(),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, buffer)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set(models_api.HeaderAuth, token)
	}
	return c.doErr(req)
}

func (c *Client) RemoveCertificate(ctx context.Context, reason, token string) error {
	u, err := url.JoinPath(c.baseUrl, "certificate")
	if err != nil {
		return err
	}
	if reason != "" {
		u += fmt.Sprintf("?reason=%s", reason)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set(models_api.HeaderAuth, token)
	}
	return c.doErr(req)
}

func (c *Client) DeployCertificate(ctx context.Context) error {
	u, err := url.JoinPath(c.baseUrl, "certificate/deploy")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, nil)
	if err != nil {
		return err
	}
	return c.doErr(req)
}

func (c *Client) doJson(req *http.Request, v any) error {
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err = getRespErr(resp); err != nil {
		return err
	}
	err = json.NewDecoder(resp.Body).Decode(v)
	if err != nil {
		_, _ = io.ReadAll(resp.Body)
		return err
	}
	return nil
}

func (c *Client) doErr(req *http.Request) error {
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err = getRespErr(resp); err != nil {
		return err
	}
	_, _ = io.ReadAll(resp.Body)
	return nil
}

func getRespErr(resp *http.Response) error {
	if resp.StatusCode >= 400 {
		b, err := io.ReadAll(resp.Body)
		if err != nil || len(b) == 0 {
			return newResponseError(resp.StatusCode, resp.Status)
		}
		return newResponseError(resp.StatusCode, string(b))
	}
	return nil
}
