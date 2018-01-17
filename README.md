MiniDNS
=======

[![Build Status](https://travis-ci.org/MiniDNS/minidns.svg)](https://travis-ci.org/MiniDNS/minidns)  [![Coverage Status](https://coveralls.io/repos/MiniDNS/minidns/badge.svg)](https://coveralls.io/r/MiniDNS/minidns)

MiniDNS is a minimal DNS client client library for Android and Java SE. It can parse most relevant resource records (A, AAAA, NS, SRV, …) and is easy to use and extend. It also provides experimental support for DNSSEC and DANE.

**Notice:** DNSSEC/DANE support is *experimental* and has not yet undergo a security audit.
If you find the project useful and are able to provide the resources for a security audit, then please contact us.

This library is not intended to be used as a DNS server. You might want to
look into dnsjava for such functionality.

Quickstart
----------

The easiest way to use MiniDNS is by its high-level API provided by the minidns-hla Maven artifact. Simply add the artifact to your projects dependencies. For example with gradle

```groovy
compile "de.measite.minidns:minidns-hla:$minidnsVersion"
```

Then you can use the `ResolverApi` class to perform DNS lookups and check if the result was authenticated via DNSSEC. The following example shows a lookup of A records of 'verteiltesysteme.net'.

```java
ResolverResult<A> result = ResolverApi.DNSSEC.resolve("verteiltesysteme.net", A.class);
if (!result.wasSuccessful()) {
	RESPONSE_CODE responseCode = result.getResponseCode();
	// Perform error handling.
	return;
}
if (!result.isAuthenticData()) {
	// Response was not secured with DNSSEC.
	return;
}
Set<A> answers = result.getAnswers();
for (A a : answers) {
  InetAddress inetAddress = a.getInetAddress();
  // Do someting with the InetAddress, e.g. connect to.
  ...
}
```

REPL
----

MiniDNS comes with a REPL which can be used to perform DNS lookups and to test the library. Simple use `./repl` to start the REPL. The loaded REPL comes with some predefined variables that you can use to perform lookups. For example `c` is a simple DNS client. See `minidns-repl/scala.repl` for more.

```text
minidns $ ./repl
...
scala> c.query("measite.de", TYPE.A)
res4: de.measite.minidns.DNSMessage = DNSMessage@54653(QUERY NO_ERROR qr rd ra) { \
  [Q: measite.de.	IN	A] \
  [A: measite.de.	3599	IN	A	85.10.226.249] \
  [X: EDNS: version: 0, flags:; udp: 512]
}
```
