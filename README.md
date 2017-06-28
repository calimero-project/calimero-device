Calimero KNX Device [![Build Status](https://travis-ci.org/calimero-project/calimero-device.svg?branch=master)](https://travis-ci.org/calimero-project/calimero-device)
===================

The Calimero KNX network stack to run a KNX device on Java SE, specifically Java SE Embedded 8. The minimum required runtime environment is 
the profile [compact1](http://www.oracle.com/technetwork/java/embedded/resources/tech/compact-profiles-overview-2157132.html) (i.e., only a subset of the full SE API).

This library allows you to implement your own KNX device on any platform that supports a JRE.

Supported Features
----

* KNX Process Communication - update KNX datapoint values, and respond to datapoint value read requests
* Device Management - application layer KNX device management services
* Device Interface Object Server - read/write KNX device properties
* KNX network access using any access protocol as supported by [calimero-core](https://github.com/calimero-project/calimero)

Download
----

~~~ sh
# Either using git
$ git clone https://github.com/calimero-project/calimero-device.git

# Or using hub
$ hub clone calimero-project/calimero-device
~~~


Example
-------

Example code of a [KNX 2-state push-button device](https://github.com/calimero-project/introduction/blob/master/src/main/java/PushButtonDevice.java) with a [quick how-to for interacting](https://github.com/calimero-project/introduction) with that KNX device.

Library Dependencies
----

* [calimero-core](https://github.com/calimero-project/calimero)
* [slf4j-api](http://www.slf4j.org/)
