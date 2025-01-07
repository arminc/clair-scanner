.PHONY : install ensure build docker rmdocker test integration integrationlinux

install:	
	go get -u golang.org/x/tools/cmd/cover
	go get -u github.com/mattn/goveralls

build:
	CGO_ENABLED=0 go build

installLocal:
	CGO_ENABLED=0 go install

cross:
	@archs="linux/386 linux/amd64 linux/arm linux/arm64 darwin/amd64 darwin/arm64"; \
	for arch in $$archs; do \
		GOOS=$$(echo $$arch | cut -d'/' -f1); \
		GOARCH=$$(echo $$arch | cut -d'/' -f2); \
		echo "Building for $$GOOS/$$GOARCH"; \
		CMD="GOOS=$$GOOS GOARCH=$$GOARCH go build -o clair-scanner_$${GOOS}_$${GOARCH}"; \
		eval $$CMD; \
	done

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
	docker pull alpine:3.20
	docker pull debian:bookworm

db:
	docker run -p 5432:5432 -d --name db arminc/clair-db:latest
	@sleep 5

clair:
	docker run -p 6060:6060 --link db:postgres -d --name clair arminc/clair-local-scan:latest
	@sleep 5

#integration: pull db clair
integration:
	go test -v -covermode=count -coverprofile=coverage.out -ip 127.0.0.1 -tags integration

#integrationlinux: pull db clair
integration:
	go test -v -covermode=count -coverprofile=coverage.out -ip 127.0.0.1 -tags integration

release: integrationlinux build cross
