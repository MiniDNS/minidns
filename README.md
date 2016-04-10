MiniDNS
=======

[![Build Status](https://travis-ci.org/rtreffer/minidns.svg)](https://travis-ci.org/rtreffer/minidns)  [![Coverage Status](https://coveralls.io/repos/rtreffer/minidns/badge.svg)](https://coveralls.io/r/rtreffer/minidns)

MiniDNS is a minimal dns client library for android. It can parse a basic set
of resource records (A, AAAA, NS, SRV) and is easy to use and extend.

This library is not intended to be used as a DNS server. You might want to
look into dnsjava for such functionality.

Quickstart
----------

The easiest way to use MiniDNS is by its high-level API. Simply add the minidns-hla Maven artifact to your projects dependencies. For example with gradle

```groovy
compile "de.measite.minidns:minidns-hla:$minidnsVersion"
```

Then you can use the `ResolverApi` like this

```java
ResolverResult<A> result = ResolverApi.DNSSEC.resolve("verteiltesysteme.net", A.class);
if (!result.wasSuccessful()) {
	RESPONSE_CODE responseCode = result.getResponseCode();
	// Error handling
	return;
}
if (!result.isAuthenticData()) {
	// Response was not secured with DNSSEC
	return;
}
Set<A> answers = result.getAnswers();
```

REPL
----

MiniDNS comes with a REPL which can be used to perform DNS lookups and to test the library. Simple use `./repl` to start the REPL.

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
