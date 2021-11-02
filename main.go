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
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/quota"
	"github.com/apigee/apigee-remote-service-golib/v2/util"
	"gopkg.in/yaml.v3"
)

const (
	RESPONSE_DELAY = time.Millisecond
)

func main() {
	var addr, host, tlsDir, configFile string
	flag.StringVar(&configFile, "config", "config.yaml", "config file")
	flag.StringVar(&host, "host", "127.0.0.1", "target host for EA (this host)")
	flag.StringVar(&addr, "addr", "", "target address (eg. ':5000'), default is random free port")
	flag.StringVar(&tlsDir, "tls", "", "directory for TLS files")
	flag.Parse()

	if addr == "" {
		p, err := util.FreePort()
		if err != nil {
			log.Fatal(err)
		}
		addr = fmt.Sprintf(":%d", p)
	}

	config := &Config{}
	err := config.load(configFile)
	if err != nil {
		log.Fatalf("unable to load config file %s: %v", configFile, err)
	}

	ts := &FileServer{
		config: config,
		host:   host,
		quotas: map[string]*quota.Result{},
	}
	defer ts.Close()
	ts.srv = &http.Server{
		Addr:    addr,
		Handler: ts.Handler(),
	}

	crd, err := ts.makeConfigCRD()
	if err != nil {
		log.Fatalf("unable to generate envoy adapter config: %v", err)
	}
	log.Printf("\n\n# Example config for Envoy Adapter:\n\n")
	if err = yaml.NewEncoder(os.Stdout).Encode(crd); err != nil {
		log.Fatalf("unable to write envoy adapter config: %v", err)
	}

	if tlsDir == "" {
		_ = ts.srv.ListenAndServe()
	} else {
		ts.hasTLS = true
		crt := path.Join(tlsDir, "tls.crt")
		key := path.Join(tlsDir, "tls.key")
		_ = ts.srv.ListenAndServeTLS(crt, key)
	}
	select {} // forever
}
