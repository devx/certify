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
	url       = flag.String("url", "https://localhost", "CFSSL URL")
	username  = flag.String("user", "", "user name to use for basic auth")
	password  = flag.String("password", "", "password to use for basic auth")
	verifySSL = flag.Bool("verifySSL", true, "Verify certificate chain")
	certType  = flag.String("type", "client-server", "The certificatle type to request: server, client, client-server")
	certName  = flag.String("name", "", "Only used for client certificates, for server and client-server we use the hostname as the identifier.")
	caCertURL = flag.String("ca_cert_url", "", "Specify an url where to downlaod the CA's certificate")
	dir       = flag.String("dir", "/etc/certificates", "directory where to store the certificates")
	force     = flag.Bool("force", false, "If certificates exist, overwrite them by requesting new certificates")
)

func main() {

	flag.Parse()

	if ok := reqClientCert(); !ok {
		log.Fatal("Failed to get retrieve a new certificate from cfssl")
	}
	os.Exit(0)
}

func reqClientCert() bool {
	log.Println("Requesting New certificates")
	jsonStr := ""

	hostname, _ := os.Hostname()

	switch *certType {
	case "client":
		if _, err := os.Stat(fmt.Sprintf("%s/%s.pem", *dir, *certName)); err == nil {
			if !*force {
				fmt.Println("File already exists exiting")
				os.Exit(0)
			}
		}
		jsonStr = fmt.Sprintf("{ \"profile\": \"%s\", \"request\": { \"CN\": \"%s\", \"hosts\": [\"\"], \"key\": { \"algo\": \"rsa\", \"size\": 2048 }, \"names\": [ { \"C\": \"US\", \"L\": \"San Antonio\", \"O\": \"test\", \"OU\": \"kumoru.org\", \"ST\": \"Texas\" } ] } } ", *certType, *certName)
	case "server", "client-server":
		if _, err := os.Stat(fmt.Sprintf("%s/%s.pem", *dir, hostname)); err == nil {
			if !*force {
				fmt.Println("File already exists exiting")
				os.Exit(0)
			}
		}
		jsonStr = fmt.Sprintf("{ \"profile\": \"%s\", \"request\": { \"CN\": \"%s\", \"hosts\": [\"%s\"], \"key\": { \"algo\": \"rsa\", \"size\": 2048 }, \"names\": [ { \"C\": \"US\", \"L\": \"San Antonio\", \"O\": \"test\", \"OU\": \"kumoru.org\", \"ST\": \"Texas\" } ] } } ", *certType, hostname, hostname)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MaxVersion:         tls.VersionTLS11,
			InsecureSkipVerify: *verifySSL,
		},
	}

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

	if !strings.Contains("https", *url) {
		fmt.Println("Please provide an https url")
		os.Exit(1)
	}

	req, _ := http.NewRequest("POST", "https://ca.kumoru.org/api/v1/cfssl/newcert",
		bytes.NewBuffer([]byte(jsonStr))) // TODO: Replace host with variable

	if user != "" {
		req.SetBasicAuth(user, pass)
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	r := new(CfsslResponse)
	if err = json.Unmarshal(body, &r); err != nil {
		log.Fatal("Failed to generage CFSLL Certificate")
	}

	fmt.Printf("CFSSL response: %+v\n", r)

	if err := ioutil.WriteFile("/etc/certificates/client.pem", []byte(r.Result.Certificate), 0644); err != nil {
		return false
	}
	if err := ioutil.WriteFile("/etc/certificates/client-key.pem", []byte(r.Result.PrivateKey), 0644); err != nil {
		return false
	}

	if getCAcert() != nil {
		return false
	}

	return true
}

func getCAcert() error {
	caURL := ""

	if os.Getenv("CA_CERT_URL") != "" {
		caURL = os.Getenv("CA_CERT_URL")
	}

	if *caCertURL != "" {
		caURL = *caCertURL

	}

	if caURL == "" {
		return nil
	}

	resp, err := http.Get(os.Getenv("CA_CERT_URL")) // TODO: Replace host with variable
	if err != nil {
		panic(err.Error())
	}
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	return ioutil.WriteFile("/etc/certificates/ca.pem", body, 0644)

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
