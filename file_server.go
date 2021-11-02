// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/key"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"gopkg.in/yaml.v2"
)

type (
	FileServer struct {
		srv       *http.Server
		quotas    map[string]*quota.Result
		quotaLock sync.Mutex
		host      string
		hasTLS    bool
		config    *Config
	}

	JWKS struct {
		Keys []jwk.Key `json:"keys"`
	}
)

func (fs *FileServer) Handler() http.Handler {
	each := func(funcs ...func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			for _, f := range funcs {
				f(w, r)
			}
		}
	}

	log := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
	}

	delay := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(RESPONSE_DELAY)
	}

	before := each(log, delay)

	m := http.NewServeMux()
	m.HandleFunc("/products", each(before, fs.handleProducts))
	m.HandleFunc("/verifyApiKey", each(before, fs.handleVerifyAPIKey))
	m.HandleFunc("/quotas", each(before, fs.handleQuotas))
	m.HandleFunc("/certs", each(before, fs.handleCerts))
	m.HandleFunc("/v1/organizations/", each(before, fs.handleSignedURL))
	m.HandleFunc("/signed-upload-url", each(before, fs.handleGCPUpload))
	m.HandleFunc("/analytics/", each(before, fs.handleSaaSUpload))
	m.HandleFunc("/version", each(before, fs.handleVersion))

	return m
}

func (fs *FileServer) handleProducts(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "application/json")
	resp := product.APIResponse{APIProducts: fs.config.APIProducts}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		writeErr(w, err, "handleProducts")
	}
}

func writeErr(w http.ResponseWriter, err error, msg string) {
	errMessage := fmt.Sprintf("error in %s: %v", msg, err)
	log.Println(errMessage)
	w.WriteHeader(500)
	w.Write([]byte(errMessage))
}

func (fs *FileServer) handleVerifyAPIKey(w http.ResponseWriter, r *http.Request) {
	var req key.APIKeyRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeErr(w, err, "handleVerifyAPIKey")
		return
	}
	defer r.Body.Close()

	if cred, ok := fs.config.Credentials[req.APIKey]; ok {
		if len(cred.Products) > 0 {
			resp, err := fs.createVerifyAPIKeyResponse(cred.Products)
			if err != nil {
				writeErr(w, err, "handleVerifyAPIKey")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				writeErr(w, err, "handleVerifyAPIKey")
				return
			}
			return
		}
	}

	w.WriteHeader(403)
}

func (fs *FileServer) handleQuotas(w http.ResponseWriter, r *http.Request) {
	var req quota.Request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeErr(w, err, "handleQuotas")
		return
	}
	defer r.Body.Close()

	fs.quotaLock.Lock()
	defer fs.quotaLock.Unlock()

	resp, ok := fs.quotas[req.Identifier]
	if !ok {
		resp = &quota.Result{}
		fs.quotas[req.Identifier] = resp
	}
	now := time.Now()
	resp.Allowed = req.Allow
	resp.Timestamp = now.UnixNano() / 1000
	if resp.Timestamp >= resp.ExpiryTime {
		resp.Used = 0
		resp.Exceeded = 0
		resp.ExpiryTime = now.Add(time.Minute).UnixNano() / 1000
	}
	resp.Used += req.Weight
	if resp.Used > resp.Allowed {
		resp.Exceeded = resp.Used - resp.Allowed
		resp.Used = resp.Allowed
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		writeErr(w, err, "handleQuotas")
		return
	}
}

func (fs *FileServer) handleCerts(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(fs.config.JWKS); err != nil {
		writeErr(w, err, "handleCerts")
		return
	}
}

func (fs *FileServer) handleSignedURL(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	url := "%s/signed-upload-url?relative_file_path=%s&tenant=%s"
	resp := map[string]interface{}{
		"url": fmt.Sprintf(url, fs.URL(), r.FormValue("relative_file_path"), r.FormValue("tenant")),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		writeErr(w, err, "handleSignedURL")
		return
	}
}

func (fs *FileServer) handleGCPUpload(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ok")); err != nil {
		writeErr(w, err, "handleGCPUpload")
		return
	}
}

func (fs *FileServer) handleSaaSUpload(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	url := "%s/signed-upload-url?relative_file_path=%s&tenant=%s"
	resp := map[string]interface{}{
		"url": fmt.Sprintf(url, fs.URL(), r.FormValue("relative_file_path"), r.FormValue("tenant")),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		writeErr(w, err, "handleSaaSUpload")
		return
	}
}

func (fs *FileServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	version := struct {
		Version string `json:"version"`
	}{
		Version: "filemock",
	}
	if err := json.NewEncoder(w).Encode(version); err != nil {
		writeErr(w, err, "handleVersion")
		return
	}
}

func (fs *FileServer) Close() { fs.srv.Close() }

func (fs *FileServer) URL() string {
	split := strings.Split(fs.srv.Addr, ":")
	var host, port string
	port = fs.srv.Addr
	if len(split) > 1 {
		host = split[0]
		port = split[1]
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if fs.host != "" {
		host = fs.host
	}
	if fs.hasTLS {
		return fmt.Sprintf("https://%s:%s", host, port)
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

func (fs *FileServer) createVerifyAPIKeyResponse(products []string) (key.APIKeyResponse, error) {
	token := jwt.New()
	_ = token.Set(jwt.AudienceKey, "remote-service-client")
	_ = token.Set(jwt.JwtIDKey, "29e2320b-787c-4625-8599-acc5e05c68d0")
	_ = token.Set(jwt.IssuerKey, "testserver")
	_ = token.Set(jwt.NotBeforeKey, time.Now().Add(-10*time.Minute).Unix())
	_ = token.Set(jwt.IssuedAtKey, time.Now().Unix())
	_ = token.Set(jwt.ExpirationKey, (time.Now().Add(10 * time.Minute)).Unix())
	_ = token.Set("access_token", "f2d45913643bccf3ad92998d06aabbd445e5376271b83fc95e5fc8515f59a5e9")
	_ = token.Set("client_id", "f2d45913643bccf3ad92998d06aabbd445e5376271b83fc95e5fc8515f59a5e9")
	_ = token.Set("application_name", "application-name")
	_ = token.Set("api_product_list", products)
	payload, err := jwt.Sign(token, jwa.RS256, fs.config.PrivateKey)

	return key.APIKeyResponse{Token: string(payload)}, err
}

func createJWKS(privateKey *rsa.PrivateKey) (*JWKS, error) {
	key, err := jwk.New(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := key.Set("kid", "1"); err != nil {
		return nil, err
	}
	if err := key.Set("alg", jwa.RS256.String()); err != nil {
		return nil, err
	}

	jwks := &JWKS{
		Keys: []jwk.Key{
			key,
		},
	}

	return jwks, nil
}

func (fs *FileServer) makeConfigCRD() (*config.ConfigMapCRD, error) {
	cfg := config.Config{
		Tenant: config.Tenant{
			InternalAPI:      fs.URL(),
			RemoteServiceAPI: fs.URL(),
			OrgName:          fs.config.Org,
			EnvName:          fs.config.Env,
			Key:              "key",
			Secret:           "secret",
		},
	}

	configYAML, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return &config.ConfigMapCRD{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: config.Metadata{
			Name:      "test-apigee-remote-service-envoy",
			Namespace: "apigee",
		},
		Data: map[string]string{"config.yaml": string(configYAML)},
	}, nil
}
