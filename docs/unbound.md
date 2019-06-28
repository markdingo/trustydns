# Configuring unbound to forward ECS queries

As discussed in [ECS](ECS.md), `trustydns-server` can be configured to add a synthetic ECS option to
queries forwarded to its resolvers. Unfortunately most resolvers remove ECS options before
forwarding queries to authoritative name servers which are the ones that actually act on
them. Fortunately the popular resolver [unbound](https://nlnetlabs.nl/projects/unbound/about/)
supports ECS forwarding. Unfortunately most distributions of unbound do not have that support
compiled in so you'll most likely have to build from sources to get this functionalty. Fortunately
that's pretty easy to do as witnessed by the brevity of this document.

To build unbound from sources with ECS forwarding enabled:

```sh
./configure --enable-subnet
make install
```

Then enable ECS in the unbound configuration with these configuration lines:

```
server:
	module-config: "subnetcache iterator"
	client-subnet-always-forward: "yes"
```

That's it.
