Calimero KNX Device [![CI with Gradle](https://github.com/calimero-project/calimero-device/actions/workflows/gradle.yml/badge.svg)](https://github.com/calimero-project/calimero-device/actions/workflows/gradle.yml)
===================

~~~ sh
git clone https://github.com/calimero-project/calimero-device.git
~~~

The Calimero KNX network stack to run a KNX device on Java SE. This library allows you to implement your own KNX device on any platform that supports a JRE. The minimum required runtime environment is [Java SE 11](https://jdk.java.net/11/) (_java.base_). 

Code examples for using this library are shown in [introduction](https://github.com/calimero-project/introduction):

* [KNX 2-state push-button device](https://github.com/calimero-project/introduction/blob/master/src/main/java/PushButtonDevice.java) 
* [Quick how-to for interacting](https://github.com/calimero-project/introduction) with the KNX device
* [Set up a device for subsequent programming (download) via ETS](https://github.com/calimero-project/introduction/blob/master/src/main/java/ProgrammableDevice.java)


Supported Features
----

* KNX Process Communication - update KNX datapoint values, and respond to datapoint value read requests from the KNX network
* Device Management - application layer KNX device management services
* Device Interface Object Server - read/write KNX device properties
* KNX network access using any access protocol as supported by [calimero-core](https://github.com/calimero-project/calimero)
* (Secure) persistance of device interface object server and memory
* Programming of Calimero KNX device via ETS (Note: this is quite dependent on the device to be programmed; the actual application logic is not interpreted in Java)

Library Dependencies
----

* [calimero-core](https://github.com/calimero-project/calimero)
