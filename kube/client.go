// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package kube provides a client to interact with Kubernetes.
package kube

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"sync"
	"time"
)

const (
	saPath     = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultURL = "https://kubernetes.default.svc"
)

func readFile(n string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Join(saPath, n))
}

// Client handles connections to Kubernetes.
// It expects to be run inside a cluster.
type Client struct {
	mu          sync.RWMutex
	url         string
	ns          string
	client      *http.Client
	token       string
	tokenExpiry time.Time
}

// New returns a new client
func New() (*Client, error) {
	ns, err := readFile("namespace")
	if err != nil {
		return nil, err
	}
	caCert, err := readFile("ca.crt")
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	if ok := cp.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("error in creating root cert pool")
	}
	return &Client{
		url: defaultURL,
		ns:  string(ns),
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: cp,
				},
			},
		},
	}, nil
}

func (c *Client) expireToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokenExpiry = time.Now()
}

func (c *Client) getOrRenewToken() (string, error) {
	c.mu.RLock()
	tk, te := c.token, c.tokenExpiry
	c.mu.RUnlock()
	if time.Now().Before(te) {
		return tk, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	tkb, err := readFile("token")
	if err != nil {
		return "", err
	}
	c.token = string(tkb)
	c.tokenExpiry = time.Now().Add(30 * time.Minute)
	return c.token, nil
}

func (c *Client) secretURL(name string) string {
	if name == "" {
		return fmt.Sprintf("%s/api/v1/namespaces/%s/secrets", c.url, c.ns)
	}
	return fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", c.url, c.ns, name)
}

func getError(resp *http.Response) error {
	if resp.StatusCode == 200 {
		return nil
	}
	st := &Status{}
	if err := json.NewDecoder(resp.Body).Decode(st); err != nil {
		return err
	}
	return st
}

func (c *Client) doRequest(method, url string, in, out interface{}) error {
	tk, err := c.getOrRenewToken()
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(in); err != nil {
			return err
		}
		body = &b
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Add("Content-Type", "application/json")
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+tk)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := getError(resp); err != nil {
		if st, ok := err.(*Status); ok && st.Code == 401 {
			c.expireToken()
		}
		return err
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// GetSecret fetches the secret from the Kubernetes API.
func (c *Client) GetSecret(name string) (*Secret, error) {
	s := &Secret{Data: make(map[string][]byte)}
	if err := c.doRequest("GET", c.secretURL(name), nil, s); err != nil {
		return nil, err
	}
	return s, nil
}

// CreateSecret creates a secret in the Kubernetes API.
func (c *Client) CreateSecret(in *Secret) error {
	in.Namespace = c.ns
	return c.doRequest("POST", c.secretURL(""), in, nil)
}

// UpdateSecret updates a secret in the Kubernetes API.
func (c *Client) UpdateSecret(in *Secret) error {
	return c.doRequest("PUT", c.secretURL(in.Name), in, nil)
}
