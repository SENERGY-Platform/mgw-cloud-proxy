package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

const authHeaderKey = "Authorization"

const hubsPath = "device-manager/hubs"

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	client       HTTPClient
	certBaseUrl  string
	tokenBaseUrl string
}

func New(httpClient HTTPClient, certBaseUrl, tokenBaseUrl string) *Client {
	return &Client{
		client:       httpClient,
		certBaseUrl:  certBaseUrl,
		tokenBaseUrl: tokenBaseUrl,
	}
}

func (c *Client) CreateNetwork(ctx context.Context, name, token string) (string, error) {
	u, err := url.JoinPath(c.selectBaseUrl(token), hubsPath)
	if err != nil {
		return "", err
	}
	buffer := bytes.NewBuffer(nil)
	err = json.NewEncoder(buffer).Encode(Network{Name: name})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, buffer)
	if err != nil {
		return "", err
	}
	setAuthHeader(req, token)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return "", NewResponseError(resp.StatusCode, b)
	}
	var network Network
	if err = json.NewDecoder(resp.Body).Decode(&network); err != nil {
		_, _ = io.ReadAll(resp.Body)
		return "", err
	}
	return network.ID, nil
}

func (c *Client) GetNetwork(ctx context.Context, id, token string) (Network, error) {
	u, err := url.JoinPath(c.selectBaseUrl(token), hubsPath, url.QueryEscape(id))
	if err != nil {
		return Network{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Network{}, err
	}
	setAuthHeader(req, token)
	resp, err := c.client.Do(req)
	if err != nil {
		return Network{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return Network{}, NewResponseError(resp.StatusCode, b)
	}
	var network Network
	if err = json.NewDecoder(resp.Body).Decode(&network); err != nil {
		_, _ = io.ReadAll(resp.Body)
		return Network{}, err
	}
	return network, nil
}

func (c *Client) selectBaseUrl(token string) string {
	if token != "" {
		return c.tokenBaseUrl
	}
	return c.certBaseUrl
}

func setAuthHeader(req *http.Request, token string) {
	if token != "" {
		req.Header.Set(authHeaderKey, token)
	}
}
