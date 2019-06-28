/*

The bestserver package tracks the performance and reliability of each server for the purpose of
identifying which server is the most reliable and has the lowest latency. This package *should* work
for any sort of latency-based set of servers (or performance which can be expressed as a
time.Duration) regardless of what they actually do.

The bestserver structure contains a list of all available servers, what a server represents, is
unknown to this package. It could be a URL, an IP address, the name of a racing pigeon... whatever.

After a server is used by the application, the application calls this package to record
success/failure and latency. That data is used internally to influence which server is chosen next.

Typical usage looks like this:

 bs := bestServer.NewLatency(Config, ServerList...) // Construct a specific bestserver container
 for {
      server, _ := bs.Best()                                                 // Get current best server
      doStuffWithServer(server.Name())                                       // Use it
      bs.Result(server, success bool, when time.Time, latency time.Duration) // Say how it went
 }

A call to Result() with the current best server causes a reassessment of the best server. Calls to
Best() will always return the same server details if no intervening calls to Result() have been
made.

Calls to Result() with a server other than the current best result in accumulation of statistics
but no reassessment of the current best.

Callers must not cache returns from Best() as that distorts the reassessment algorithm.

There are currently two types of "best servers" to choose from: 'latency' and 'traditional' which
are created with the obviously named NewLatency() and NewTraditional() functions respectively. They
each implement different algorithms when choosing a new best server. This package is structured to
make it easy to add additional algorithms if the need arises.

The 'latency' algorithm generally tries to gravitate towards the lowest latency server by
opportunistically sampling all servers to collect statistics on their performance. The selection
algorithm is:

 - the first server on the list starts as the 'best' server

 - a reassessment occurs if any of the following conditions are true:
    o the current 'best' server is given an unsuccessful result
    o the configured reassessment timer has expired
    o the configured number of Result() calls have been reached

Reassessment chooses the server with the lowest weighted average latency to become the new 'best'
server.

To ensure there is latency data for all server, after a Result() call, Best() will periodically
return a non-'best' server to gather performance information for that server. The default sample
rate at which non-'best' servers are returned is approximately 5% of the time.

Servers which are unsuccessful as indicated by Result() calls are excluded from this sampling
process for a configured time period.

The expectation is that there are a relatively small number of servers as much of the selection
algorithm is a simple linear search of all entries and thus O(n). A server list of 10-20 is
reasonable, 1,000-10,000 is probably not.

The 'traditional' implementation created with NewTraditional() is intended to mimic nameserver
selection by res_send(3) as described in RESOLVER(3). That is, the first server is used until it
fails then the next server is used until it fails and so on. Once the end of the server list is
reached, then the algorithm wraps around to the first server and the process repeats.

Multiple goroutines can safely invoke all the Manager interface methods concurrently.
*/
package bestserver
