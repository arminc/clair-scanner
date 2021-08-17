#!/bin/bash
set -ueo pipefail

cd "$(dirname "$0")"

log_error() { echo -e "\033[0m\033[1;91m${*}\033[0m"; }
log_success() { echo -e "\033[0m\033[1;92m${*}\033[0m"; }

image=${1:-}

if [[ -z "${image:-}" ]] || ! [[ "${image:-}" =~ : ]]; then
  log_error "must specify image:version to scan"
  exit 1
fi

function scanner_docker_build() {
  echo $'
    FROM amazonlinux:2
    RUN curl -L \
        https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_linux_amd64 \
        -o clair-scanner && \
        chmod +x ./clair-scanner
  ' | docker build -t clair-scanner -
}

if ! scanner_docker_build >/dev/null 2>&1; then
  scanner_docker_build
fi

function scanner_docker_compose() {
  echo $'
    version: "3"
    services:
      postgres:
        image: arminc/clair-db:latest
        networks:
          - clair-local
        restart: always
      clair:
        image: arminc/clair-local-scan:latest
        networks:
          - clair-local
        restart: always
    networks:
      clair-local:
        driver: bridge
  ' | docker-compose -f - "${@}"
}

if ! scanner_docker_compose pull >/dev/null 2>&1; then
  scanner_docker_compose pull
fi

if ! scanner_docker_compose up -d >/dev/null 2>&1; then
  scanner_docker_compose up -d
fi

report_file=$(echo "${image:?}.json" | sed  's/\W/-/g')

trap "scanner_docker_compose down > /dev/null 2>&1" int exit

reports=$(mktemp -d)

function scan() {
  local image="${1:?}"
  docker run \
    -ti \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "${reports:?}:/reports" \
    --rm \
    --network="$(basename "$(pwd)")"_clair-local \
    clair-scanner \
    bash -c """
     while ! curl -q http://clair:6060 > /dev/null 2>&1; do
       sleep 1
     done
      ./clair-scanner --ip \${HOSTNAME:?} -r /reports/${report_file:?} --clair http://clair:6060 \"${image:?}\"
    """
}

if scan "${image:?}"; then
  log_success "✨ ${image:?} contains no known vulnerabilities. ✨"
else
  log_error "😱 ${image:?} contains vulnerabilities, details saved to ${reports:?}/${report_file:?}. 😱"
  exit 1
fi
