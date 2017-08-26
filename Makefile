.PHONY : install ensure build docker

install:
	go get -u github.com/golang/dep/cmd/dep

ensure:
	dep ensure

build:
	go build

docker: 
	@cd docker && \
		docker build -t golang-cross-compile .

cross: docker
	docker run -ti --rm -v $(CURDIR):/gopath/src/clair-scanner -w /gopath/src/clair-scanner golang-cross-compile gox -osarch="darwin/amd64 darwin/386 linux/amd64 linux/386 windows/amd64 windows/386"

clean: 
	rm clair-scanner*