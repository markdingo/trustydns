# Running trustydns on Windows

Warning: The authors are complete neophytes when it comes to Windows. Any help appreciated. The
follow comments are based on testing with a 32bit Windows7 instance.

The main message is that the trustydns *does* run on Windows, but it's not as pretty as we'd like.

For cross-compiling the [Makefile](../Makefile) includes targets for 'windowsamd64' and 'windows386'
which produce `.exe` files. These `.exe` files can then be transferred to your Windows
system. Alternatively you can download `go` and compile natively. Both approaches are known to
produce working executables.

Regardless of the mechanism by which you create executables, the main issue runnng them is dealing
with missing directories and files assumed to be present by the various commands. Specifically:

* No TLS root certificate directory thus the need to run with `--tls-use-system-roots=false` for all commands
* No resolv.conf file thus the need to create and identify one for `trustydns-server` using `-c resolv.conf`

Our guess is that this data lives in the Registry and as such is not available via the file
system. If anyone wants to offer code which accesses this data via the correct mechanism within
Windows we will gladly accept it.

A further limitation is that `go test` fails on Windows as the tests assume the presence of the
aforementioned files and directories and they also currently assume a Unix signal
environment. You'll have to take it on faith that a successful `go test` on a Unix system is
sufficient.

It also has to be said that all the commands are particularly "unixy" in that they still use
`-short-option` and `--long-option` as opposed to Windows switches. This is due to the use of the
standard go `flag` package. Is there an alternate package which use a platform-appropriate syntax
rather than a hard-coded Unix syntax? That is one which accepts `/short-option` and `/long-option'
for Windows? If so, let us know or better yet create a pull request with the patches to use it.

