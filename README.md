# ejbca

This is a fork of PrimeKey EJBCA community edition, from v 6.15.2.6

Goals are:

* Change build system from ant to maven
* Get it building under Java 11
* Get it working on up-to-date app servers (Wildfly 19, Payara 5, Tomcat 9)
* Improve test coverage
* Add system-level tests with Selenium

NOTE REGARDING CERT-CVC

The version of EJBCA this is forked from depends on CERT-CVC v1.4.9. As of the time of writing,
the most recent CERT-CVC in Central is v1.4.6, and I have been unable to locate the v1.4.9 source. 
The V1.4.9 Jar from the original download is therefore included and installed to the local repo by the build.
Should PrimeKey release v1.4.9 with source, it will be included here and built as a module.

![Maven Package](https://github.com/winterknight1979/ejbca/workflows/Maven%20Package/badge.svg)
