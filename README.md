Calimero KNX Device [![Build Status](https://travis-ci.org/calimero-project/calimero-device.svg?branch=master)](https://travis-ci.org/calimero-project/calimero-device)
===================

The Calimero KNX network stack to run a KNX device on Java SE. This library allows you to implement your own KNX device on any platform that supports a JRE. The minimum required runtime environment is Java SE Embedded 8 with the profile [compact1](http://www.oracle.com/technetwork/java/embedded/resources/tech/compact-profiles-overview-2157132.html) (i.e., only a subset of the full SE API). 

A code example for using this library is shown in [introduction](https://github.com/calimero-project/introduction):

* [KNX 2-state push-button device](https://github.com/calimero-project/introduction/blob/master/src/main/java/PushButtonDevice.java) 
* [Quick how-to for interacting](https://github.com/calimero-project/introduction) with the KNX device


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


Library Dependencies
----

* [calimero-core](https://github.com/calimero-project/calimero)
* [slf4j-api](http://www.slf4j.org/)
