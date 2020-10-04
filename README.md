# ejbca

![Merge branch to master](https://github.com/winterknight1979/ejbca/workflows/Merge%20branch%20to%20master/badge.svg)![Maven Release](https://github.com/winterknight1979/ejbca/workflows/Maven%20Release/badge.svg)[![codecov](https://codecov.io/gh/winterknight1979/ejbca/branch/master/graph/badge.svg?token=J3QRD54ZIG)](https://codecov.io/gh/winterknight1979/ejbca)[![Codacy Badge](https://app.codacy.com/project/badge/Grade/a32150f8b3f84479abd27e6bd0820cbf)](https://www.codacy.com/gh/winterknight1979/ejbca/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=winterknight1979/ejbca&amp;utm_campaign=Badge_Grade)

This is a fork of PrimeKey EJBCA community edition, from v 6.15.2.6

Goals are:

* Change build system from ant to maven
* Get it building under Java 11
* Get it working on up-to-date app servers (Wildfly 19, Payara 5, Tomcat 9)
* Fix some securtity issues (not good in a CA application!)
* Use CDI beans instead of deprecated JSF beans
* Improve test coverage
* Add system-level tests with Selenium

NOTE REGARDING CERT-CVC

The version of EJBCA this is forked from depends on CERT-CVC v1.4.9. As of the time of writing,
the most recent CERT-CVC in Central is v1.4.6, and I have been unable to locate the v1.4.9 source. 
The V1.4.9 Jar from the original download is therefore included and installed to the local repo by the build.
Should PrimeKey release v1.4.9 with source, it will be included here and built as a module.




