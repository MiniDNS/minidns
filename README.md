MiniDNS - A DNSSEC enabled DNS library
======================================

[![Build Status](https://github.com/MiniDNS/minidns/workflows/CI/badge.svg)](https://github.com/MiniDNS/minidns/actions?query=workflow%3A%22CI%22)  [![Coverage Status](https://coveralls.io/repos/MiniDNS/minidns/badge.svg)](https://coveralls.io/r/MiniDNS/minidns)

MiniDNS ("**M**odular **I**nternet **N**ame **I**nformer for **DNS**") is a DNS library for Android and Java SE. It can parse resource records (A, AAAA, NS, SRV, …) and is easy to use and extend. MiniDNS aims to be secure, modular, efficient and as simple as possible. It also provides support for **DNSSEC** and **DANE**, and is thus the ideal resolver if you want to bring DNSSEC close to your application.

It comes with a pluggable cache mechanism, a pre-configured cache and an easy to use high-level API (`minidns-hla`) for those who just want to perform a reliable lookup of a domain name.

**Notice:** DNSSEC/DANE support has not yet undergo a security audit.
If you find the project useful and if you are able to provide the resources for a security audit, then please contact us.

If you are looking for a DNSSEC-enabled resolver in C (and/or Lua) then hava a look at the [Knot Resolver](https://www.knot-resolver.cz/). Also this library is not intended to be used as a DNS server. You might want to
look into [dnsjava](http://dnsjava.org/) for such functionality.

**MiniDNS release resources** (javadoc, …) an be found at https://minidns.org/releases

Quickstart
----------

The easiest way to use MiniDNS is by its high-level API provided by the minidns-hla Maven artifact. Simply add the artifact to your projects dependencies. For example with gradle

```groovy
compile "org.minidns:minidns-hla:$minidnsVersion"
```

Then you can use the `ResolverApi` or `DnssecResolverApi` class to perform DNS lookups and check if the result was authenticated via DNSSEC. The following example shows a lookup of A records of 'verteiltesysteme.net'.

```java
ResolverResult<A> result = DnssecResolverApi.INSTANCE.resolve("verteiltesysteme.net", A.class);
if (!result.wasSuccessful()) {
	RESPONSE_CODE responseCode = result.getResponseCode();
	// Perform error handling.
	…
	return;
}
if (!result.isAuthenticData()) {
	// Response was not secured with DNSSEC.
	…
	return;
}
Set<A> answers = result.getAnswers();
for (A a : answers) {
  InetAddress inetAddress = a.getInetAddress();
  // Do someting with the InetAddress, e.g. connect to.
  …
}
```

MiniDNS also provides full support for SRV resource records and their handling.

```java
SrvResolverResult result = DnssecResolverApi.INSTANCE.resolveSrv(SrvType.xmpp_client, "example.org")
if (!result.wasSuccessful()) {
	RESPONSE_CODE responseCode = result.getResponseCode();
	// Perform error handling.
	…
	return;
}
if (!result.isAuthenticData()) {
	// Response was not secured with DNSSEC.
	…
	return;
}
List<ResolvedSrvRecord> srvRecords = result.getSortedSrvResolvedAddresses();
// Loop over the domain names pointed by the SRV RR. MiniDNS will return the list
// correctly sorted by the priority and weight of the related SRV RR.
for (ResolvedSrvRecord srvRecord : srvRecord) {
	// Loop over the Internet Address RRs resolved for the SRV RR. The order of
	// the list depends on the prefered IP version setting of MiniDNS.
	for (InternetAddressRR inetAddressRR : srvRecord.addresses) {
		InetAddress inetAddress = inetAddressRR.getInetAddress();
		int port = srvAddresses.port;
		// Try to connect to inetAddress at port.
		…
	}
}
```

REPL
----

MiniDNS comes with a REPL which can be used to perform DNS lookups and to test the library. Simple use `./repl` to start the REPL. The loaded REPL comes with some predefined variables that you can use to perform lookups. For example `c` is a simple DNS client. See `minidns-repl/scala.repl` for more.

```text
minidns $ ./repl
...
scala> c query ("measite.de", TYPE.A)
res0: dnsqueryresult.DnsQueryResult = DnsMessage@54653(QUERY NO_ERROR qr rd ra) { \
  [Q: measite.de.	IN	A] \
  [A: measite.de.	3599	IN	A	85.10.226.249] \
  [X: EDNS: version: 0, flags:; udp: 512]
}
```
