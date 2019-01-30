.PHONY : install ensure build docker rmdocker test integration integrationlinux

dbosx:
	docker run -p 5432:5432 -d --name db arminc/clair-db:$(shell date -v-1d +%Y-%m-%d)
	@sleep 5

db:
	docker run -p 5432:5432 -d --name db arminc/clair-db:$(shell date -d "-1 day" +%Y-%m-%d)
	@sleep 5

clair:
	docker run -p 6060:6060 --link db:postgres -d --name clair arminc/clair-local-scan:v2.0.6
	@sleep 5

integration:
	go test -v -covermode=count -coverprofile=coverage.out -ip $(shell ipconfig getifaddr en0) -tags integration

integrationlinux: pull db clair
	go test -v -covermode=count -coverprofile=coverage.out -ip $(shell ifconfig eth0 | grep "inet addr" | cut -d ':' -f 2 | cut -d ' ' -f 1) -tags integration

release: integrationlinux build cross

docker:
	docker build -t golang-cross-compile docker

docker-cross:
	docker run -ti --rm -v $(CURDIR):/clair-scanner -w /clair-scanner golang-cross-compile cross-compile

docker-cross-compile: 
	export GOOS=darwin && export GOARCH=amd64 && go build -o dist/clair-scanner_darwin_amd64	
	export GOOS=darwin && export GOARCH=386 && go build -o dist/clair-scanner_darwin_386
	export GOOS=linux && export GOARCH=amd64 && go build -o dist/clair-scanner_linux_amd64
	export GOOS=linux && export GOARCH=386 && go build -o dist/clair-scanner_linux_386
	export GOOS=windows && export GOARCH=amd64 && go build -o dist/clair-scanner_windows_amd64.exe
	export GOOS=windows && export GOARCH=386 && go build -o dist/clair-scanner_windows_386.exe
