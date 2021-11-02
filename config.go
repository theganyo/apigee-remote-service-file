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
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"log"
	"os"

	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Org         string                        `yaml:"org"`
	Env         string                        `yaml:"env"`
	APIProducts []product.APIProduct          `yaml:"apiProducts"`
	Apps        map[string]App                `yaml:"apps"`
	PrivateKey  *rsa.PrivateKey               `yaml:"-"`
	JWKS        *JWKS                         `yaml:"-"`
	Products    map[string]product.APIProduct `yaml:"-"`
	Credentials map[string]Credential         `yaml:"-"`
}

type App struct {
	Developer   string       `yaml:"dev"`
	Credentials []Credential `yaml:"credentials"`
}

type Credential struct {
	Key      string   `yaml:"key"`
	Secret   string   `yaml:"secret"`
	Products []string `yaml:"products"`
}

func (c *Config) load(configFile string) (err error) {
	var data []byte
	if data, err = ioutil.ReadFile(configFile); err != nil {
		return err
	}
	if err = yaml.Unmarshal(data, c); err != nil {
		return
	}
	if c.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return
	}
	c.JWKS, err = createJWKS(c.PrivateKey)

	c.Products = make(map[string]product.APIProduct)
	for _, p := range c.APIProducts {
		c.Products[p.Name] = p
	}

	c.Credentials = make(map[string]Credential)
	for _, app := range c.Apps {
		for _, cred := range app.Credentials {
			c.Credentials[cred.Key] = cred
		}
	}

	// log
	if err := yaml.NewEncoder(os.Stdout).Encode(c); err != nil {
		log.Fatal(err)
	}

	return
}
