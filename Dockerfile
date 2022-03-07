FROM alpine:3.15.0

COPY ./docker_configs/entrypoint.sh /bin/entrypoint.sh
COPY ./clair-scanner/ /clair-scanner/
RUN apk update && apk add \
    curl \
    zip \
    alpine-sdk \
    ca-certificates \
    git\
    mercurial \
    breezy \
    go \
    && rm -rf /var/cache/apk/*

ENV GOVERSION 1.17.4
RUN mkdir /goroot && mkdir /gopath
RUN curl https://storage.googleapis.com/golang/go${GOVERSION}.linux-amd64.tar.gz \
    | tar xvzf - -C /goroot --strip-components=1

ENV GOPATH /gopath
ENV GOROOT /goroot
ENV PATH $GOROOT/bin:$GOPATH/bin:$PATH

RUN go get github.com/mitchellh/gox

RUN cd clair-scanner && make build
RUN mv clair-scanner/clair-scanner /bin/ && \
    cd && \
    rm -rf clair-scanner

