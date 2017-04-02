# Clair scanner

## Docker containers vulnerability scan

When you work with containers (Docker) you are not only packaging your application but also part of the OS. Therefore it is crucial to know what kind of libraries might be vulnerable in you container. One way to find this information is to use and look at the Docker Hub or Quay.io security scan. The problem whit these scans is that they are only showing you the information but are not part of your CI/CD that actually blocks your container when it contains vulnerabilities.

What you want is:

1. Build and test your application
1. Build the container
1. Test the container for vulnerabilities
1. Check the vulnerabilities against allowed ones, if everything is allowed pass, otherwise fail

This straight forward process is not that easy to achieve when using the services like Docker Hub or Quay.io. Docker Hub does not have an API and Quay.io triggers afterwards and therefore makes it harder to do straight forward CI/CD pipeline. (Although it is possible to achieve this with Quay.io because they have a web hook that notifies you about the vulnerabilities).

## Clair to the rescue

CoreOS has created an awesome container scan tool called "clair". Clair is also used by Quay.io. What clair does not have is a simpel tool that scans your image and compares the vulnerabilities against a whitelist to see if they are approved or not.

This is where clair-scanner comes in to place. The clair-scanner does the following:

* Scans an image against Clair server
* Compares the vulnerabilities against a whitelist
* Tells you if there are vurnabilities that are not in the whitelist and fails
* If everything is fine it completes correctly

## Clair server or standalone

For the clair-scanner to work you need a clair server. It is not always convenient to have a dedicated clair server therefore I have created a way to run this standalone. See here <https://github.com/arminc/clair-local-scan>

## Credits

The clair-scanner is a copy of the Clair 'analyze-local-images' <https://github.com/coreos/clair/tree/master/contrib/analyze-local-images> with changes/improvments and addition that checks the vulnerabilities against a whitelist.
