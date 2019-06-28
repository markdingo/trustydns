# TODO List for trustydns

A dumping ground for unresolved issues and discussion topics.

## The Bootstrap Problem

How should `trustydns-proxy` be deployed if the DNS lookups cannot be trusted in the first place? It
has no easy way of determining the correct IP addresses for the DoH URLs. Most likely we'll need to
introduce a configuration or command-line option specifying the IP addresses to use. We could
annotate the URL with something like: https://dohserver/dns-query@10.1.2.3. This could work since we
know that the DoH URL is heavily constrained anyway.

Unfortunately there doesn't seem to be an easy way of achieving this with Go's net/http package
unless we replace the RoundTripper which is a monster activity. What we really want to do is control
the DNS lookup but that's embedded deep within the Transport package. Changing the
http.Request.URL.Host to an IP doesn't work as that is used to form the URL
https://IPAddress/dns-query which fails TLS unless the remote certificate also contains an "IP SANs"
- whatever that is.

## Loopback Query Protection

It's a relatively easy mistake to configure the proxy to send split-domain queries back to
itself. To check for this, the proxy could issue a query of ${uuid}.example.net to the local
resolver and see if it shows up on the listen side. This may not be foolproof if there are multiple
nameservers entries only some of which point back to the proxy. There is also no easy way of
encoding loop detection into the dns query as we risk that encoding leaking out to a "real" resolver
and possibly causing undesirable responses.

## Multiple client Credentials for the proxy

Strictly, there should be separate client TLS credentials for each private DoH server used by the
proxy. As it stands the proxy can only load one set of credentials to use with all DoH
servers. Let's see if multiple private DoH servers become common before worrying about this.

## Client Revocation

I can't see a way to uniquely identify client certificates *and* access that unique identity on the
server side thus there is no facility to revoke a client certificate without revoking the root CA
and starting again. TLS must have a way of identify TLS clients - but is that accessible in Go?

## Solve Package Dependency with go mod

We should upgrade to using `go mod` for package dependency. Fortunately there are few dependency
thus far so this isn't critical.

## setuid/setgid is broken on Linux

Not really a trustydns problem, more a victim of it, but on Linux programs written in Go cannot
discard root privileges needed to open privileged network sockets. This is normal security practice
on Unix. If you attempt a priviledge downgrade with the trustydns daemons (via `--user` and
`--group`) they generate a warning but continue to run with elevated privileges. This is not a
problem on any other Unix platform.

## miekg/dns.Client Optimization

Should resolver/local have a pool of dns.Clients or net.Conns?  Currently each Resolv() call results
in a socket setup and teardown when there are typically a known (and small) set of local resolvers
which are very amenable to connection pooling.

## go testing for main() is klunky and brittle

The go testing frame-work is not well suited to testing executables. the main commands have been
structured to make it possible to use the go framework to test things like usage use-cases but they
are still more brittle than I would like. Perhaps an alternative testing framework should be
considered for these tests?
