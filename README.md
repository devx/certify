#Certify
A small utility that will request certificates from CFSSL and write the certificates to a specific directory.
```
certify -h 

Usage of certify:
  -ca_cert_url string
        Specify an url where to downlaod the CA's certificate
  -dir string
        directory where to store the certificates (default "/etc/certificates")
  -force
        If certificates exist, overwrite them by requesting new certificates (default: false)
  -name string
        Only used for client certificates, for server and client-server we use the hostname as the identifier.
  -password string
        password to use for basic auth
  -skipSSL
        Verify certificate chain (default: false)
  -type string
        The certificatle type to request: server, client, client-server (default "client-server")
  -url string
        CFSSL URL (default "https://localhost")
  -user string
        user name to use for basic auth

```

#How to use:
Request a client and if certificates exist overwrite them. 
```
certify -dir $(pwd) -name client-test -user USER -password SUPER_SECRET_PASSWORD -url https://my.certiciate.ca  -type client -force true 
```


Request a server certificate it will use the hostname as the CN ie: myserver.example.com
```
certify -dir $(pwd) -name client-test -user USER -password SUPER_SECRET_PASSWORD -url https://my.certiciate.ca  -type server
```

#Notes:
To make this more generic some things need to be changed.
##TODO:
 - [ ] make certificate properties load from a config file or environment variables
 - [ ] add test
