BUILD_FLAGS :=  "-s -w"
SYSTEM = `uname -s`
default: clean build

linux-binary:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags $(BUILD_FLAGS) -o builds/Linux/certify cmd/certify/main.go

osx-binary:
	@CGO_ENABLED=0 GOOS=darwin go build -a -installsuffix cgo  -ldflags $(BUILD_FLAGS) -o builds/Darwin/certify cmd/certify/main.go

build:
	@go build -a -ldflags $(BUILD_FLAGS) -o builds/$(SYSTEM)/certify cmd/certify/main.go

install: build mv-bin

mv-bin:
	@cp builds/${SYSTEM}/certify ${GOPATH}/bin/

clean:
	rm -f cmd/certify/certify
	rm -f builds/Darwin/certify
	rm -f builds/Linux/certify

restore:
	godep restore

depsave:
	rm -f Godeps/Godeps.json
	godep save

test:
	go test -cover ./...

container: clean linux-binary
	docker build -t quay.io/devx/certify:latest .

release: clean restore test osx-binary linux-binary
