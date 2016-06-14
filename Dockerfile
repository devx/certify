FROM alpine:3.3
RUN apk -U add ca-certificates
ADD builds/Linux/certify /usr/bin/certify
VOLUME /etc/certificates
