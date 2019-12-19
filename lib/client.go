package lib

import (
	"crypto/tls"
	"net/http"
)

type Client struct {
	ServerURL  string
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
		ServerURL: serverURL,
		// We don't need to set a connection timeout
		httpClient: &http.Client{},
	}
}

func (c *Client) Create() {

}
