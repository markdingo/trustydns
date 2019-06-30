## DNS Over HTTPS proxy, server and query programs

Trustydns is a DNS Over HTTPS (DoH) package written in Go. The proxy and server programs can be
combined to create a completely independent DoH eco-system or they can be mixed and matched
with other DoH components. Trustydns is intended to comply with RFC8484 but has additional
non-standard features which can be optionally enabled.


[![Build Status](https://travis-ci.org/markdingo/trustydns.svg?branch=master)](https://travis-ci.org/markdingo/trustydns)
[![Go Report Card](https://goreportcard.com/badge/github.com/markdingo/trustydns)](https://goreportcard.com/report/github.com/markdingo/trustydns)
[![codecov](https://codecov.io/gh/markdingo/trustydns/branch/master/graph/badge.svg)](https://codecov.io/gh/markdingo/trustydns)

## Programs

The `trustydns-proxy` daemon accepts regular DNS queries and forwards them to a DoH server over
HTTPS. Typically `trustydns-proxy` is installed on your home or office gateway and replaces your
local resolver. It could also be installed on your portable devices if you roam on to untrusted
networks. The `trustydns-server` daemon accepts DoH queries and forwards them to a local
resolver. It is normally installed on a remote, trusted system which has access to a trusted
resolver. Finally, the `trustydns-dig` command-line utility issues DoH queries and can be used to
test DoH servers.

## Anticipated deployment

While these programs can be mixed and matched with existing DoH infrastructure such as those
provided by Quad9 and Mozilla, the intent is to let you create your own DoH eco-system independent
of all external parties. In particular, the programs have been written in Go expressly so they can
be easily cross-compiled for targets such as home routers which do not normally provide a
development environment. Sample cross-compile targets can be found in the [Makefile](./Makefile).

Trustydns supports both server-side and client-side TLS certificates so you can set up a completely
closed system whereby only appropriately credentialed proxies and servers can exchange DoH queries
with each other.

Additional deployment features which may be of interest include:

 * Split-horizon DNS settings to ensure local domain queries stay local
 * EDNS Client Subnet (RFC7871) controls for masking, substitution and synthesis
 * Support for alternate root CAs to enable private certificates
 * Proxy support for a pool of DoH servers so no single point of failure

## Caveats

Trustydns is new and has some rough edges to it. It does not yet use `go mod` to manage dependencies
(fortuitously there are few package dependencies) and the compilation and installation process is
simplistic at best.

This package is targeted at DNS administrators with a modicum of Unix sysadmin experience. You need
not be an expert to deploy trustydns but there are many different ways a DoH installation can be
constructed such that this document can at best offer general guidance and hints.

Some features have been deferred prior to gaining more real-world deployment experience to assess
how desirable they truly are. These are discussed in the [TODO](docs/TODO.md) document.

The alternate root CA support is definitely "primordial". Let's see how useful it is before making
too much of a meal out of it. It may turn out that this feature is more hassle than it's worth in
which case it may be removed in a future release.

## Installation

This package should compile and run on most Unix-like systems which support go1.12.1 or higher. All
programs have been tested on various CPU architectures with FreeBSD, Linux and macOS. The
[Makefile](./Makefile) in the root directory is a very simple affair which builds and installs the programs into
`/usr/local/{sbin|bin}`. Feel free to modify it to suit your environment.

To fetch, compile and install trustydns, run the following commands:

```sh
go get github.com/markdingo/trustydns   # Ignore the warning about no go programs

cd $GOPATH/src/github.com/markdingo/trustydns

make updatepackages        # Make sure dependent Go packages are installed and current
make clean all             # Compile everything
sudo make install          # Install programs into /usr/local
```

## Getting Started

The proxy and server daemons are designed to be run by a process supervision manager such as
[daemontools](http://cr.yp.to/daemontools.html), launchd, runit or systemd; how you do this is up to
you. Prior to deployment though you can test all the trustydns programs from the command line and
even do so without needing to obtain a TLS certifcate!  First start the server with:

`/usr/local/sbin/trustydns-server -A 127.0.0.1:8080 --log-all -v`

The server should start accepting DoH queries over HTTP on port 8080 and resolve those queries via
the resolvers in `/etc/resolv.conf`.

Use `trustydns-dig` to send a DoH query to your freshly running server:

`/usr/local/bin/trustydns-dig http://127.0.0.1:8080/dns-query yahoo.com mx`

If all goes well `trustydns-dig` returns the MX RRs for Yahoo! and you should see some
log chatter from the server as it processes the query. The log chatter is mostly of use to
developers but it's helpful here to demonstrate server activity.

The final step is to incorporate the proxy into the query flow. Start it with:

`/usr/local/sbin/trustydns-proxy -A 127.0.0.1:6653 -v --log-all http://127.0.0.1:8080/dns-query`

The proxy should start accepting DNS queries on port 6653 and forward them to your
`trustydns-server` instance on port 8080. To test the proxy, use your preferred DNS query tool to
issue a regular query to port 6653, e.g:

`dig -p 6653 @127.0.0.1 yahoo.com mx`

If all goes *really* well, the DNS query returns the MX RRs for Yahoo! which closely matches your
previous `trustydns-dig` query. Both the proxy and the server should chatter away with their logging
output showing "proof of life".

If you've got this far, congratulations! You've successfully run all the programs and are now ready
to deploy.


## Server Certificate

As you no doubt observed in "Getting Started", all the programs can use HTTP which expedites the
learning exercise and greatly simplfies traffic debugging. However if you plan to run
`trustydns-server` in production you'll need to acquire a TLS server certificate and invoke
`trustydns-server` with `--tls-cert` and `--tls-key`.

You should be able to use any of: an official paid-for certificate generated by a commercial CA,
"free" certificates from https://letsencrypt.org or a self-signed certificate generated by a tool
such as `openssl`. For reference, the author runs `trustydns-server` with a "Let's Encrypt"
certificated generated with [certbot](https://certbot.eff.org). For those that want to take the self-signed
route there are a few scripts in the [openssl](./openssl) directory which might help.

If you plan to run a "proxy only" deployment which relies on existing DoH Servers you will of course
not need a Server Certificate.

## Deployments Scenarios

### A Proxy-only Deployment

One possible deployment scenario is to use `trustydns-proxy` on your local network and direct its
DoH queries to public DoH servers such as those run by Mozilla and Quad9. To do this invoke the proxy
as follows:

```sh
/usr/local/sbin/trustydns-proxy -v https://mozilla.cloudflare-dns.com/dns-query \
                                   https://dns.quad9.net/dns-query
```

The proxy accepts DNS queries on port 53 and forward them to one of the servers on the command line
depending on which is offering reliable responses with the lowest latency. `trustydns-proxy`
opportunistically forwards queries to different servers to accumulate latency and reliability data.

There are other public DoH servers besides those run by Mozilla and Quad9. A fairly comprehensive
list can be found on the [Curl GitHub site](https://github.com/curl/curl/wiki/DNS-over-HTTPS). Note
that at the time of writing, Google do *not* run a public RFC8484 compliant DNS Over HTTPS
server. They run a DNS Over HTTPS API of their own invention which is not supported by trustydns.

### A Proxy deployment with split-DNS

It's not un-common for a network to have a "split-DNS" whereby lookups of your local domain produce
different results from those seen by the "outside" world. This is usually achieved with a special
local resolver configuration.

`trustydns-proxy` supports split-DNS environments with the `-c` and `-e` options. Here is an example
invocation:

```sh
/usr/local/sbin/trustydns-proxy -v -c /etc/resolv.conf \
                                   -e example.net -e 168.192.in-addr.arpa \
                                   https://mozilla.cloudflare-dns.com/dns-query \
                                   https://dns.quad9.net/dns-query
```

This invocation causes `trustydns-proxy` to redirect all queries for the search/domains in
`/etc/resolv.conf` as well as the domains "example.net" and "168.192.in-addr.arpa" to the resolvers
specified in /etc/resolv.conf. All other queries are forwarded to the DoH servers on the command
line. Redirection to local resolvers also includes all sub-domains of the specified domains.

**WARNING:** Make very sure that the proxy listen address is not included in the nominated
resolv.conf file otherwise redirected queries will cause an unpleasant query loop.


### Private Proxy and Server Deployment

A private proxy/server deployment is one in which both the proxy and server use privately generated
certificates to authorize access to each other. If we assume that you have previously generated a
rootCA and server and proxy certificates - perhaps with the help of the supplied [openssl
scripts](./openssl/README.md) - then proxy invocation looks something like:

```sh
/usr/local/sbin/trustydns-proxy -v --tls-key proxy.key --tls-cert proxy.cert \
                                   --tls-other-roots rootCA.cert --tls-use-system-roots=false \
                                   --log-tls-errors \
                                   https://$yourDoHServer/dns-query
```

While not essential the `--log-tls-errors` option is useful for identifying certificate verification
failures.

and server invocation is something like:

```sh
/usr/local/sbin/trustydns-server -v --tls-key $yourDoHServer.key --tls-cert $yourDoHServer.cert \
                                    --tls-other-roots rootCA.cert --tls-use-system-roots=false \
                                    --log-tls-errors
```

Setting `--tls-use-system-roots=false` retricts access solely to certificates generated with your
root CA.


## Reporting Tools

In verbose mode (-v) both the server and the proxy produce periodic statistic output which will
normally be written to log files. There are a number of scripts in the [tools](./tools) directory
which can produce summary reports from the log files. For details see
[tools/README](tools/README.md).


## Other Documents

There are various ancilliary documents in the [docs](docs/.) directory which cover more obscure
aspects of running trustydns.  They cover things like how to build and configure
[unbound](https://nlnetlabs.nl/projects/unbound) to support ECS queries and how to enable ECS
synthesis to improve GSLB responses.

## Copyright and License

Trustydns is Copyright :copyright: 2019 Mark Delany. This software  is licensed under the BSD 2-Clause "Simplified" License.
