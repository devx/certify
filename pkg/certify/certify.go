/*
Copyright 2016 Victor Palma

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certify

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

//Config represents the configuration which is used by various Certify functions.
type Config struct {
	CAURL    string
	CertName string
	CertType string
	Force    bool
	Password string
	SkipSSL  bool
	URL      string
	Username string
}

// CfsslResponse struct
type CfsslResponse struct {
	Success bool `json:"success"`
	Result  struct {
		Certificate        string `json:"certificate"`
		CertificateRequest string `json:"certificate_request"`
		PrivateKey         string `json:"private_key"`
		Sums               struct {
			Certificate struct {
				Md5  string `json:"md5"`
				Sha1 string `json:"sha-1"`
			} `json:"certificate"`
			CertificateRequest struct {
				Md5  string `json:"md5"`
				Sha1 string `json:"sha-1"`
			} `json:"certificate_request"`
		} `json:"sums"`
	} `json:"result"`
	Errors   []interface{} `json:"errors"`
	Messages []interface{} `json:"messages"`
}

//RequestClientCert attempts to retrieve a certificate from CFSSL
func (c *Config) RequestClientCert() (*CfsslResponse, error) {
	JSONstr := c.buildCertReq()

	log.Println("Requesting New certificates")
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/cfssl/newcert", c.URL),
		bytes.NewBuffer([]byte(JSONstr)))

	if err != nil {
		log.Fatalf("Error requesting new certificate: %s", err)
	}

	user, pass := c.basicAuth()
	if user != "" {
		req.SetBasicAuth(user, pass)
	}

	tr := &http.Transport{}

	if strings.Contains(c.URL, "https") {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{
				MaxVersion:         tls.VersionTLS11,
				InsecureSkipVerify: c.SkipSSL,
			},
		}
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	r := new(CfsslResponse)

	if err = json.Unmarshal(body, &r); err != nil {
		return nil, err
	}

	return r, nil

}

func (c *Config) buildCertReq() string {
	jsonStr := ""

	switch c.CertType {
	case "client":
		jsonStr = fmt.Sprintf("{ \"profile\": \"%s\", \"request\": { \"CN\": \"%s\", \"hosts\": [\"\"], \"key\": { \"algo\": \"rsa\", \"size\": 2048 }, \"names\": [ { \"C\": \"US\", \"L\": \"San Antonio\", \"O\": \"test\", \"OU\": \"kumoru.org\", \"ST\": \"Texas\" } ] } } ", c.CertType, c.CertName)
	case "server", "client-server":
		hostname, _ := os.Hostname()
		jsonStr = fmt.Sprintf("{ \"profile\": \"%s\", \"request\": { \"CN\": \"%s\", \"hosts\": [\"%s\"], \"key\": { \"algo\": \"rsa\", \"size\": 2048 }, \"names\": [ { \"C\": \"US\", \"L\": \"San Antonio\", \"O\": \"test\", \"OU\": \"kumoru.org\", \"ST\": \"Texas\" } ] } } ", c.CertType, hostname, hostname)
	}

	return jsonStr
}

func (c *Config) basicAuth() (string, string) {
	user := ""
	pass := ""

	if os.Getenv("CFSSL_USERNAME") != "" {
		user = os.Getenv("CFSSL_USERNAME")
		pass = os.Getenv("CFSSL_PASSWORD")
	}

	if c.Username != "" {
		user = c.Username
		pass = c.Password
	}

	return user, pass
}

//GetCA retrieves a CA certificate
func (c *Config) GetCA() ([]byte, error) {
	if c.CAURL == "" {
		return []byte(c.CAURL), nil
	}

	resp, err := http.Get(c.CAURL)
	if err != nil {
		panic(err.Error())
	}

	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	return body, nil
}
