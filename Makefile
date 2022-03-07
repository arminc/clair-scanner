.DEFAULT_GOAL := help

SHELL = /bin/bash

CLAIR_IMAGE        = toucantoco/clair-scanner
CLAIR_VERSION_FILE = version.txt
CLAIR_VERSION      = v`cat $(CLAIR_VERSION_FILE)`
QUAYIO_IMAGE       = $(CLAIR_IMAGE)
QUAYIO_REGISTRY    = quay.io

##
## Misc commands
## -----
##

list: ## Generate basic list of all targets
	@grep '^[^\.#[:space:]].*:' Makefile | \
		grep -v "=" | \
		cut -d':' -f1

help: ## Makefile help
	@grep -E '(^[a-zA-Z_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | \
		sed -e 's/\[32m##/[33m/'

get-version: ## Display current clair-scanner version
	@echo $(CLAIR_VERSION)

set-version: ## Set NEW_VERSION as the new clair-scanner version
	@if [ -z "$(NEW_VERSION)" ]; then \
		echo "Usage: make set-version NEW_VERSION=X.Y.Z" && \
		exit 1; \
	fi
	@echo "$(NEW_VERSION)" | sed -e "s/^v//g" > $(CLAIR_VERSION_FILE)


##
## Docker images commands
## -----
##

docker-build-prod:  ## Build the prod image
	docker build --tag ${CLAIR_IMAGE}:${CLAIR_VERSION} .

push-to-registry:  ## Push production image to dockerhub
	for tag in ${CLAIR_VERSION} ${CLAIR_IMAGE_MORE_TAGS}; do \
		docker tag ${CLAIR_IMAGE}:${CLAIR_VERSION} ${QUAYIO_REGISTRY}/${QUAYIO_IMAGE}:$${tag} && \
		docker push ${QUAYIO_REGISTRY}/${QUAYIO_IMAGE}:$${tag}; \
	done
