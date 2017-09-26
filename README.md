# Clair scanner

![Maintenance](https://img.shields.io/maintenance/yes/2017.svg)
[![Build Status](https://travis-ci.org/arminc/clair-scanner.svg?branch=master)](https://travis-ci.org/arminc/clair-scanner)
[![Go Report Card](https://goreportcard.com/badge/github.com/arminc/clair-scanner)](https://goreportcard.com/report/github.com/arminc/clair-scanner)
[![Coverage Status](https://coveralls.io/repos/github/arminc/clair-scanner/badge.svg?branch=master)](https://coveralls.io/github/arminc/clair-scanner?branch=master)

## Docker containers vulnerability scan

When you work with containers (Docker) you are not only packaging your application but also part of the OS. It is crucial to know what kind of libraries might be vulnerable in your container. One way to find this information is to look at the Docker registry [Hub or Quay.io] security scan. This means your vulnerable image is already on the Docker registry.

What you want is a scan as a part of CI/CD pipeline that stops the Docker image push on vulnerabilities:

1. Build and test your application
1. Build the container
1. Test the container for vulnerabilities
1. Check the vulnerabilities against allowed ones, if everything is allowed then pass otherwise fail

This straightforward process is not that easy to achieve when using the services like Docker Hub or Quay.io. This is because they work asynchronously which makes it harder to do straightforward CI/CD pipeline.

## Clair to the rescue

CoreOS has created an awesome container scan tool called Clair. Clair is also used by Quay.io. What clair does not have is a simple tool that scans your image and compares the vulnerabilities against a whitelist to see if they are approved or not.

This is where clair-scanner comes into place. The clair-scanner does the following:

* Scans an image against Clair server
* Compares the vulnerabilities against a whitelist
* Tells you if there are vulnerabilities that are not in the whitelist and fails
* If everything is fine it completes correctly

## Clair server or standalone

For the clair-scanner to work, you need a clair server. It is not always convenient to have a dedicated clair server, therefore, I have created a way to run this standalone. See here <https://github.com/arminc/clair-local-scan>

## Credits

The clair-scanner is a copy of the Clair 'analyze-local-images' <https://github.com/coreos/analyze-local-images> with changes/improvements and addition that checks the vulnerabilities against a whitelist.

## Build

clair-scanner is built with Go 1.9 and uses `dep` as dependencies manager. Use the Makefile to build and install dependencies.

```bash
make ensure && make build
```

Cross compile:

```bash
make cross
```

## Run

Example of a container scan, start Clair:

```bash
docker run -p 5432:5432 -d --name db arminc/clair-db:2017-09-18
docker run -p 6060:6060 --link db:postgres -d --name clair arminc/clair-local-scan:v2.0.1
```

Now scan a container, that has a whitelisted CVE (this is on OSX with Docker for Mac):

```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```

Output:

```bash
2017/09/24 11:20:24 [INFO] ▶ Start clair-scanner
2017/09/24 11:20:24 [INFO] ▶ Server listening on port 9279
2017/09/24 11:20:24 [INFO] ▶ Analyzing 693bdf455e7bf0952f8a4539f9f96aa70c489ca239a7dbed0afb481c87cbe131
2017/09/24 11:20:24 [INFO] ▶ Image [alpine:3.5] not vulnerable
```

Or a container that does not have a whitelisted CVE (this is on OSX with Docker for Mac):

```bash
clair-scanner --ip YOUR_LOCAL_IP alpine:3.5
```

Output:

```bash
2017/09/24 11:16:41 [INFO] ▶ Start clair-scanner
2017/09/24 11:16:41 [INFO] ▶ Server listening on port 9279
2017/09/24 11:16:41 [INFO] ▶ Analyzing 693bdf455e7bf0952f8a4539f9f96aa70c489ca239a7dbed0afb481c87cbe131
2017/09/24 11:16:41 [CRIT] ▶ Image contains unapproved vulnerabilities: [CVE-2016-9840 CVE-2016-9841 CVE-2016-9842 CVE-2016-9843]
```

## Help information

```bash
$ ./clair-scanner -h

Usage: clair-scanner [OPTIONS] IMAGE

Scan local Docker images for vulnerabilities with Clair

Arguments:
  IMAGE=""     Name of the Docker image to scan

Options:
  -w, --whitelist=""                    Path to the whitelist file
  -c, --clair="http://127.0.0.1:6060"   Clair URL
  --ip="localhost"                      IP address where clair-scanner is running on
  -l, --log=""                          Log to a file
  -r, --report=""                       Report output file, as JSON
```

## Example whitelist yaml file

This is an example yaml file. You can have an empty file or a mix with only `generalwhitelist` or `images`.

```yaml
generalwhitelist: #Approve CVE for any image
  CVE-2017-6055: XML
  CVE-2017-5586: OpenText
images:
  ubuntu: #Apprive CVE only for ubuntu image, regardles of the version
    CVE-2017-5230: Java
    CVE-2017-5230: XSX
  alpine:
    CVE-2017-3261: SE
```

## Release

To make a release create a tag and push it.