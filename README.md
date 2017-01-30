Calimero KNX Device [![Build Status](https://travis-ci.org/calimero-project/calimero-device.svg?branch=master)](https://travis-ci.org/calimero-project/calimero-device)
===================

KNX network stack to run a KNX device.

This feature branch adapts the KNX device to use the Calimero library builds for Java SE Embedded 8.

Download
--------

~~~ sh
# Either using git
$ git clone https://github.com/calimero-project/calimero-device.git

# Or using hub
$ hub clone calimero-project/calimero-device
~~~

Supported Features
--------

* Process Communication - update values of KNX datapoints, and respond to datapoint value read requests
* Device Management - application layer KNX device management services
* Interface Object Server - read/write KNX device properties
* KNX network access using any access protocol supported by Calimero (see [calimero-core](https://github.com/calimero-project/calimero))


Example
-------

Example code of a [2-state push-button actuator](https://github.com/calimero-project/introduction/blob/master/examples/java8/PushButtonActuator.java) with a [quick how-to for testing](https://github.com/calimero-project/introduction).

Dependencies
------------

* [calimero-core](https://github.com/calimero-project/calimero)
* [slf4j-api](http://www.slf4j.org/)
