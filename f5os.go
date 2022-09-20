/*
Copyright 2022 F5 Networks Inc.
This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/
// Package f5os interacts with F5OS systems using the OPEN API.
package f5os

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	uriRoot           = "/restconf/data"
	uriLogin          = "/restconf/data/openconfig-system:system/aaa"
	contentTypeHeader = "application/yang-data+json"
)

var defaultConfigOptions = &ConfigOptions{
	APICallTimeout: 60 * time.Second,
}

type ConfigOptions struct {
	APICallTimeout time.Duration
}

type F5osConfig struct {
	Host      string
	User      string
	Password  string
	Port      int
	Transport *http.Transport
	// UserAgent is an optional field that specifies the caller of this request.
	UserAgent     string
	Teem          bool
	ConfigOptions *ConfigOptions
}

// F5os is a container for our session state.
type F5os struct {
	Host      string
	Token     string // if set, will be used instead of User/Password
	Transport *http.Transport
	// UserAgent is an optional field that specifies the caller of this request.
	UserAgent     string
	Teem          bool
	ConfigOptions *ConfigOptions
}

// APIRequest builds our request before sending it to the server.
type APIRequest struct {
	Method      string
	URL         string
	Body        string
	ContentType string
}

// Upload contains information about a file upload status
type Upload struct {
	RemainingByteCount int64          `json:"remainingByteCount"`
	UsedChunks         map[string]int `json:"usedChunks"`
	TotalByteCount     int64          `json:"totalByteCount"`
	LocalFilePath      string         `json:"localFilePath"`
	TemporaryFilePath  string         `json:"temporaryFilePath"`
	Generation         int            `json:"generation"`
	LastUpdateMicros   int            `json:"lastUpdateMicros"`
}

// RequestError contains information about any error we get from a request.
type RequestError struct {
	Code       int      `json:"code,omitempty"`
	Message    string   `json:"message,omitempty"`
	ErrorStack []string `json:"errorStack,omitempty"`
}

// Error returns the error message.
func (r *RequestError) Error() error {
	if r.Message != "" {
		return errors.New(r.Message)
	}

	return nil
}

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	// fmt.Println("Welcome to init() function")
}

// NewSession sets up connection to the F5os system.
func NewSession(f5osObj *F5osConfig) (*F5os, error) {
	var url string
	f5osSession := &F5os{}
	if !strings.HasPrefix(f5osObj.Host, "http") {
		url = fmt.Sprintf("https://%s", f5osObj.Host)
	} else {
		url = f5osObj.Host
	}
	url = fmt.Sprintf("%s:%d", url, 8888)
	if f5osObj.Port != 0 {
		url = fmt.Sprintf("%s:%d", url, f5osObj.Port)
	}
	if f5osObj.ConfigOptions == nil {
		f5osObj.ConfigOptions = defaultConfigOptions
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	f5osSession.Host = url
	f5osSession.Transport = tr
	f5osSession.ConfigOptions = f5osObj.ConfigOptions
	client := &http.Client{
		Transport: tr,
	}
	method := "GET"
	url = fmt.Sprintf("%s%s", url, uriLogin)
	req, err := http.NewRequest(method, url, nil)
	req.Header.Set("Content-Type", contentTypeHeader)
	req.SetBasicAuth(f5osObj.User, f5osObj.Password)
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	f5osSession.Token = res.Header.Get("X-Auth-Token")
	_, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return f5osSession, nil
}

// APICall is used to query the BIG-IP web API.
func (p *F5os) APICall(options *APIRequest) ([]byte, error) {
	var req *http.Request
	client := &http.Client{
		Transport: p.Transport,
		Timeout:   p.ConfigOptions.APICallTimeout,
	}
	url := fmt.Sprintf("%s%s", p.Host, options.URL)
	body := bytes.NewReader([]byte(options.Body))
	req, _ = http.NewRequest(strings.ToUpper(options.Method), url, body)
	req.Header.Set("X-Auth-Token", p.Token)
	if len(options.ContentType) > 0 {
		req.Header.Set("Content-Type", options.ContentType)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return io.ReadAll(res.Body)
}
func (p *F5os) doRequest(op, path string, body []byte) ([]byte, error) {
	log.Trace().Msgf("Entering f5os.doRequest")
	defer log.Trace().Msgf("Exiting f5os.doRequest")

	log.Trace().Msgf("path = %s", path)
	if len(body) > 0 {
		log.Trace().Msgf("body = %s", string(body))
	}
	req, err := http.NewRequest(op, path, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", p.Token)
	req.Header.Set("Content-Type", contentTypeHeader)
	client := &http.Client{
		Transport: p.Transport,
		Timeout:   p.ConfigOptions.APICallTimeout,
	}
	// req.Header.Add("Content-Type", "application/yang-data+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (p *F5os) GetRequest(path string) ([]byte, error) {
	log.Trace().Msgf("Entering f5os.GetRequest")
	defer log.Trace().Msgf("Exiting f5os.GetRequest")
	url := fmt.Sprintf("%s%s%s", p.Host, uriRoot, path)
	return p.doRequest("GET", url, nil)
}

func (p *F5os) DeleteRequest(path string) error {
	log.Trace().Msgf("Entering f5os.DeleteRequest")
	defer log.Trace().Msgf("Exiting f5os.DeleteRequest")
	url := fmt.Sprintf("%s%s%s", p.Host, uriRoot, path)
	if resp, err := p.doRequest("DELETE", url, nil); err != nil {
		return err
	} else if len(resp) > 0 {
		log.Debug().Msgf("DeleteRequest output = %s", string(resp))
	}
	return nil
}

func (p *F5os) PatchRequest(path string, body []byte) ([]byte, error) {
	log.Trace().Msgf("Entering f5os.PatchRequest")
	defer log.Trace().Msgf("Exiting f5os.PatchRequest")
	url := fmt.Sprintf("%s%s%s", p.Host, uriRoot, path)
	return p.doRequest("PATCH", url, body)
}

func (p *F5os) PostRequest(path string, body []byte) ([]byte, error) {
	log.Trace().Msgf("Entering f5os.PostRequest")
	defer log.Trace().Msgf("Exiting f5os.PostRequest")
	url := fmt.Sprintf("%s%s%s", p.Host, uriRoot, path)
	return p.doRequest("POST", url, body)
}
