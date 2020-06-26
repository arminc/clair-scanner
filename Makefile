.PHONY : install ensure build docker rmdocker test integration integrationlinux

install:	
	go get -u golang.org/x/tools/cmd/cover
	go get -u github.com/mattn/goveralls

build:
	CGO_ENABLED=0 go build

installLocal:
	CGO_ENABLED=0 go install

docker:
	@cd docker && \
		docker build -t golang-cross-compile .

cross: docker
	docker run -ti --rm -e CGO_ENABLED=0 -v $(CURDIR):/gopath/src/clair-scanner -w /gopath/src/clair-scanner golang-cross-compile gox -osarch="darwin/amd64 darwin/386 linux/amd64 linux/386 windows/amd64 windows/386" -output "dist/{{.Dir}}_{{.OS}}_{{.Arch}}"

clean:
	rm -rf dist

rmdocker:
	-docker kill clair
	-docker kill db
	-docker rm clair
	-docker rm db

test:
	go test

pull:
	docker pull alpine:3.5
	docker pull debian:jessie

db:
	docker run -p 5432:5432 -d --name db arminc/clair-db:latest
	@sleep 5

clair:
	docker run -p 6060:6060 --link db:postgres -d --name clair arminc/clair-local-scan:latest
	@sleep 5

integration: pull db clair
	go test -v -covermode=count -coverprofile=coverage.out -ip $(shell ipconfig getifaddr en0) -tags integration

integrationlinux: pull db clair
	go test -v -covermode=count -coverprofile=coverage.out -ip $(shell ifconfig docker0 | grep "inet addr" | cut -d ':' -f 2 | cut -d ' ' -f 1) -tags integration

release: integrationlinux build cross
