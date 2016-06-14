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
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	caURL    = flag.String("caURL", "", "Specify an url where to downlaod the CA's certificate")
	certName = flag.String("name", "", "Only used for client certificates, for server and client-server we use the hostname as the identifier.")
	certType = flag.String("type", "client-server", "The certificatle type to request: server, client, client-server")
	dir      = flag.String("dir", "/etc/certificates", "directory where to store the certificates")
	force    = flag.Bool("force", false, "If certificates exist, overwrite them by requesting new certificates (default: false)")
	password = flag.String("password", "", "password to use for basic auth")
	skipSSL  = flag.Bool("skipSSL", false, "Verify certificate chain (default: false)")
	url      = flag.String("url", "https://localhost", "CFSSL URL")
	username = flag.String("user", "", "user name to use for basic auth")
)

func main() {

	flag.Parse()

	if ok := reqClientCert(); !ok {
		log.Fatal("Failed to get retrieve a new certificate from cfssl")
	}
	os.Exit(0)
}

func reqClientCert() bool {
	cert, JSONstr := buildCertReq()

	log.Println("Requesting New certificates")
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/cfssl/newcert", *url),
		bytes.NewBuffer([]byte(JSONstr)))

	user, pass := basicAuth()
	if user != "" {
		req.SetBasicAuth(user, pass)
	}

	tr := &http.Transport{}

	if strings.Contains(*url, "https") {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{
				MaxVersion:         tls.VersionTLS11,
				InsecureSkipVerify: *skipSSL,
			},
		}
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("%s\n", err)
		os.Exit(1)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	r := new(CfsslResponse)

	if err = json.Unmarshal(body, &r); err != nil {
		log.Fatal("Failed to generage CFSSL Certificate")
	}

	if err := ioutil.WriteFile(fmt.Sprintf("%s.pem", cert), []byte(r.Result.Certificate), 0644); err != nil {
		return false
	}
	if err := ioutil.WriteFile(fmt.Sprintf("%s-key.pem", cert), []byte(r.Result.PrivateKey), 0644); err != nil {
		return false
	}

	if getCAcert() != nil {
		return false
	}

	return true
}

func buildCertReq() (string, string) {
	c := ""
	jsonStr := ""
	switch *certType {
	case "client":
		c = fmt.Sprintf("%s/%s", *dir, *certName)
		if _, err := os.Stat(fmt.Sprintf("%s.pem", c)); err == nil {
			if !*force {
				fmt.Println("File already exists exiting")
				os.Exit(0)
			}
		}
		jsonStr = fmt.Sprintf("{ \"profile\": \"%s\", \"request\": { \"CN\": \"%s\", \"hosts\": [\"\"], \"key\": { \"algo\": \"rsa\", \"size\": 2048 }, \"names\": [ { \"C\": \"US\", \"L\": \"San Antonio\", \"O\": \"test\", \"OU\": \"kumoru.org\", \"ST\": \"Texas\" } ] } } ", *certType, *certName)
	case "server", "client-server":
		hostname, _ := os.Hostname()
		c = fmt.Sprintf("%s/%s.pem", *dir, hostname)
		if _, err := os.Stat(fmt.Sprintf("%s.pem", c)); err == nil {
			if !*force {
				fmt.Println("File already exists exiting")
				os.Exit(0)
			}
		}
		jsonStr = fmt.Sprintf("{ \"profile\": \"%s\", \"request\": { \"CN\": \"%s\", \"hosts\": [\"%s\"], \"key\": { \"algo\": \"rsa\", \"size\": 2048 }, \"names\": [ { \"C\": \"US\", \"L\": \"San Antonio\", \"O\": \"test\", \"OU\": \"kumoru.org\", \"ST\": \"Texas\" } ] } } ", *certType, hostname, hostname)
	}
	return c, jsonStr
}

func basicAuth() (string, string) {
	user := ""
	pass := ""

	if os.Getenv("CFSSL_USERNAME") != "" {
		user = os.Getenv("CFSSL_USERNAME")
		pass = os.Getenv("CFSSL_PASSWORD")
	}

	if *username != "" {
		user = *username
		pass = *password
	}

	return user, pass
}

func getCAcert() error {
	caURLstr := ""

	if os.Getenv("CA_CERT_URL") != "" {
		caURLstr = os.Getenv("CA_CERT_URL")
	}

	if *caURL != "" {
		caURLstr = *caURL

	}

	if caURLstr == "" {
		return nil
	}

	resp, err := http.Get(caURLstr) // TODO: Replace host with variable
	if err != nil {
		panic(err.Error())
	}
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	return ioutil.WriteFile(fmt.Sprintf("%s/ca.pem", *dir), body, 0644)

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
