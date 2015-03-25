use Net::DNS;

my $r = Net::DNS::Resolver->new();

# This script is provided as a reference. It's not really part of the
# minidns source code. Rather, the files it downloaded when _I_ ran it
# today form part of the source, and the junit tests verify that
# minidns interprets those exact packets the same way that I do.

# If you rerun the script, you may get other results than I did in
# January 2015. Several of them likely depend on geolocation and load
# balancing.

# In short: If you update the packets you'll have to interpret them
# correctly and update the interpretation tests appropriately.


# do one DNS lookup and write the query packet to a file

sub lookup() {
    my ($domain, $type, $filename) = @_;

    my $p = $r->query($domain, $type);

    # print for visibility during test analysis
    print $p->string;

    open F, ">$filename" or die "$!\n";
    print F $p->data;
    close F;
}


# SRV and MX are near and dear to me

&lookup("gmail.com", "mx", "gmail-mx");
&lookup("_xmpp-client._tcp.gulbrandsen.priv.no", "srv", "gpn-srv");

# A matters to everyone

# sunracle uses a CNAME now, which affords an opportunity to test for
# an attack
&lookup("www.sun.com", "a", "sun-a");
# we'll modify the answer and change one AD RR, and then check that a
# direct lookup is not affected (ie. our cache isn't poisoned)
&lookup("legacy-sun.oraclegha.com", "a", "sun-real-a");

# AAAA doubles in importance every few months
&lookup("google.com", "aaaa", "google-aaaa");

&lookup("oracle.com", "soa", "oracle-soa");
