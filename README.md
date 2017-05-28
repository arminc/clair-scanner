# Clair scanner

![Build Status](https://img.shields.io/maintenance/yes/2017.svg)

## Docker containers vulnerability scan

When you work with containers (Docker) you are not only packaging your application but also part of the OS. Therefore it is crucial to know what kind of libraries might be vulnerable in you container. One way to find this information is to use and look at the Docker Hub or Quay.io security scan. The problem whit these scans is that they are only showing you the information but are not part of your CI/CD that actually blocks your container when it contains vulnerabilities.

What you want is:

1. Build and test your application
1. Build the container
1. Test the container for vulnerabilities
1. Check the vulnerabilities against allowed ones, if everything is allowed pass, otherwise fail

This straight forward process is not that easy to achieve when using the services like Docker Hub or Quay.io. This is because they work asynchronously which makes it harder to do straight forward CI/CD pipeline.

## Clair to the rescue

CoreOS has created an awesome container scan tool called "clair". Clair is also used by Quay.io. What clair does not have is a simple tool that scans your image and compares the vulnerabilities against a whitelist to see if they are approved or not.

This is where clair-scanner comes in to place. The clair-scanner does the following:

* Scans an image against Clair server
* Compares the vulnerabilities against a whitelist
* Tells you if there are vurnabilities that are not in the whitelist and fails
* If everything is fine it completes correctly

## Clair server or standalone

For the clair-scanner to work you need a clair server. It is not always convenient to have a dedicated clair server therefore I have created a way to run this standalone. See here <https://github.com/arminc/clair-local-scan>

## Credits

The clair-scanner is a copy of the Clair 'analyze-local-images' <https://github.com/coreos/clair/tree/master/contrib/analyze-local-images> with changes/improvments and addition that checks the vulnerabilities against a whitelist.

## Build

To build clair-scanner first you need to initialize vendor dependencies by using glide <https://glide.sh/>

```bash
glide install
```

And then it's simpel as running

```bash
go build
```

Cross compile:

```bash
docker run -ti --rm -v "$(pwd)":/gopath/src/clair-scanner -w /gopath/src/clair-scanner tcnksm/gox:1.7
```

## Run

Example of a container scan, start Clair:

```bash
docker run -p 5432:5432 -d --name db arminc/clair-db:2017-05-05
docker run -p 6060:6060 --link db:postgres -d --name clair arminc/clair-local-scan:v2.0.0
```

Now scan a container, that has a whitelisted CVE:

```bash
clair-scanner nginx:1.11.6-alpine example-nginx.yaml http://YOUR_LOCAL_IP:6060 YOUR_LOCAL_IP
```

Or a container that does not have a whitelisted CVE:

```bash
clair-scanner nginx:1.11.6-alpine example-whitelist.yaml http://YOUR_LOCAL_IP:6060 YOUR_LOCAL_IP
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