# Copyright 2016 Victor Palma
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
