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
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/devx/certify/pkg/certify"
)

type cliConfig struct {
	certify.Config
	Dir string
}

var config cliConfig

func init() {
	caURL := ""

	if os.Getenv("CA_CERT_URL") != "" {
		caURL = os.Getenv("CA_CERT_URL")
	}

	flag.StringVar(&config.CAURL, "caURL", caURL, "Specify an url where to downlaod the CA's certificate (default: ENV 'CA_CERT_URL')")
	flag.StringVar(&config.CertName, "name", "", "Only used for client certificates, for server and client-server we use the hostname as the identifier.")
	flag.StringVar(&config.CertType, "type", "client-server", "The certificatle type to request: server, client, client-server")
	flag.StringVar(&config.Dir, "dir", "/etc/certificates", "directory where to store the certificates")
	flag.BoolVar(&config.Force, "force", false, "If certificates exist, overwrite them by requesting new certificates (default: false)")
	flag.StringVar(&config.Password, "password", "", "password to use for basic auth")
	flag.BoolVar(&config.SkipSSL, "skipSSL", false, "Verify certificate chain (default: false)")
	flag.StringVar(&config.URL, "url", "https://localhost", "CFSSL URL")
	flag.StringVar(&config.Username, "user", "", "user name to use for basic auth")

	flag.Parse()

}

func main() {

	certLocation := ""

	switch config.CertType {
	case "client":
		certLocation = fmt.Sprintf("%s/%s.pem", config.Dir, config.CertName)
	case "server", "client-server":
		hostname, _ := os.Hostname()
		certLocation = fmt.Sprintf("%s/%s.pem", config.Dir, hostname)
	}

	validateFileOverride(certLocation)
	getCA()
	getCert()

	os.Exit(0)
}

func validateFileOverride(file string) {
	if _, err := os.Stat(file); err == nil {
		if !config.Force {
			log.Fatalf("File %s already exists, exiting\n", file)
			os.Exit(1)
		}
	}
}

func getCA() {
	CAresponse, err := config.GetCA()

	if err != nil {
		log.Fatalf("Failed to get retrieve CA certificate: %s", err)
		os.Exit(1)
	}

	if err := ioutil.WriteFile(fmt.Sprintf("%s/ca.pem", config.Dir), CAresponse, 0644); err != nil {
		log.Fatalf("Error writing file: %s", err)
		os.Exit(1)
	}
}

func getCert() {
	CFSSLResponse, err := config.RequestClientCert()

	if err != nil {
		log.Fatalf("Failed to get retrieve a new certificate from cfssl: %s", err)
		os.Exit(1)
	}

	if err := ioutil.WriteFile(fmt.Sprintf("%s.pem", config.CertName), []byte(CFSSLResponse.Result.Certificate), 0644); err != nil {
		log.Fatalf("Error writing file: %s", err)
		os.Exit(1)
	}

	if err := ioutil.WriteFile(fmt.Sprintf("%s-key.pem", config.CertName), []byte(CFSSLResponse.Result.PrivateKey), 0644); err != nil {
		log.Fatalf("Error writing file: %s", err)
		os.Exit(1)
	}
}
