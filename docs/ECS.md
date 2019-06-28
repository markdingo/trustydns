# DoH reduces GSLB effectiveness - ECS increases GSLB effectiveness

[RFC8484](https://tools.ietf.org/html/rfc8484) is silent on the matter of EDNS0 Client Subnet
[(ECS)](https://tools.ietf.org/html/rfc7871). This is understandable given the provenance of DoH
which was borne into existence mostly as a simple secure DNS tunnel. But this silence is less
explicable given ECS mitigates against one of the biggest performance disadvantages of DoH - that it
results in sub-optimal answers from
[GSLBs](https://www.a10networks.com/resources/articles/global-server-load-balancing) and
[CDNs](https://en.wikipedia.org/wiki/Content_delivery_network).

By their very nature DoH servers are likely to be topologically distant from their clients. That
means GSLB answers well-suited to the DoH server location may not be well-suited to the client
location. This answer discrepancy is the main reason ECS came into existence in the first place so
it stands to reason that ECS is especially relevant to DoH.

In the absence of guidance from RFC8484, trustydns has taken the liberty of adding a number of
features which let you manipulate ECS to help overcome the performance disadvantages of DoH.

## ECS Synthesis

The most beneficial feature is to enable ECS Synthesis in the `trustydns-server` by setting the
`--ecs-set` option (and possibly the `--ecs-remove` option). With this option set,
`trustydns-server` synthesizes an ECS option in the out-going query with the HTTPS client IP
address. If the query makes it to a GSLB intact, then the GSLB will provide an answer best-suited to
the client IP address.

ECS Synthesis is performed on the server as it sees the true *routable address* of the client
whereas a proxy or client on the inside of a local network may not have that ability, particularly if the
local network is sitting behind a NAT or CG-NAT.

ECS Sythesis can also be reguested by `trustydns-proxy` with the `ecs-request-*` options. In this
case the proxy uses non-standard HTTP headers to signal the Synthesis Request to a
`trustydns-server` instance. This approach lets each proxy deployment decide whether to use ECS or
not rather than have the server arbitrarily synthesize ECS for all proxies. Naturally ECS Synthesis
triggered by `trustydns-proxy` only works when it is sending DoH queries to a `trustydns-server`.

## Privacy

The privacy implication of ECS Synthesis is that the client's IP address (or at least a masked
version of it) is visible to the server-side resolvers and authoritative name servers used during
resolution. This obvious exposure of the client's IP is a potential security risk. For that reason
ECS Synthesis has to be specifically enabled by one of the aforementioned options. Furthermore, if
there is any concern that local clients might be generated ECS options which you'd rather not
expose, both the proxy and server have options to remove all ECS options prior to forwarding
queries.

## Effectiveness

Whether ECS Synthesis is effective or not depends on a number of factors. In particular whether the
resolver used by the server forwards ECS options thru to authoritative servers. Many resolvers
cannot forward ECS options. An exception is unbound so there is a [brief document](./unbound.md)
explaining how to activate that feature. Also, ECS is only supported by some GSLBs or only supported
on an opt-in basis. So all in all the effectiveness of ECS Synthesis may not be as significant as
you might wish. To gain insights into ECS effectiveness the proxy and server produce periodic ECS
statistics.


## A word of warning about IPv6 and GSLBs

Many GSLBs rely on geo-IP databases such as those provided by [Akamai
Edgescape](https://developer.akamai.com/edgescape), [Maxmind](https://www.maxmind.com/) and
[IP2Location](https://www.ip2location.com). While these databases tends to have around an 80% level
of accuracy for IPv4 they are much less accurate with IPv6 networks. In part this is because many
end-user networks are using ISP-delegated IPv6 address space rather than purchasing their own
portable allocations. This means the GEO IP database providers have no whois information to scrape -
a significant source of their geo-IP location data.

The net result from a DoH perspective is that even though ECS Synthesis can mitigate against the
performance disadvantages of DoH, for IPv6 it may be some time before mitigation is on par with
IPv4.
