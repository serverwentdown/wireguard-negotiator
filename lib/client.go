package lib

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

var ErrRequestFailed = fmt.Errorf("request for peer config was not successful")

type Client struct {
	serverURL  string
	httpClient *http.Client
}

func NewClient(serverURL string, insecure bool) *Client {
	httpClient := &http.Client{}
	if insecure {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return &Client{
		serverURL: serverURL,
		// Client is not used in time or resource sensitive environments, therefore
		// omitting timeout reduces code
		httpClient: &http.Client{},
	}
}

func (c *Client) Request(publicKey string) (PeerConfigResponse, error) {
	peerConfigRequest := url.Values{}
	peerConfigRequest.Set("PublicKey", publicKey)

	resp, err := c.httpClient.PostForm(c.serverURL+"/request", peerConfigRequest)
	if err != nil {
		return PeerConfigResponse{}, fmt.Errorf("unable to request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return PeerConfigResponse{}, ErrRequestFailed
	}
	decoder := json.NewDecoder(resp.Body)

	var peerConfigResponse PeerConfigResponse
	err = decoder.Decode(&peerConfigResponse)
	if err != nil {
		return PeerConfigResponse{}, fmt.Errorf("unable to request: %w", err)
	}

	return peerConfigResponse, nil
}
