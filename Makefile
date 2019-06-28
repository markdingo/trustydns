# This is just a dumb makefile that provides a few short-hand build targets and install
# destinations. It's not meant to be robust or efficient or even particularly flexible, but
# hopefully the simplicity makes it easy for you to use and modify to suit your own needs.
#
# This makefile also has a few examples of how to cross-compile the executables for other
# architectures, such as home routers.

daemondest=/usr/local/sbin
cmddest=/usr/local/bin
cmddirs=cmd/trustydns-dig cmd/trustydns-proxy cmd/trustydns-server
commands=cmd/trustydns-server/trustydns-server cmd/trustydns-proxy/trustydns-proxy cmd/trustydns-dig/trustydns-dig

targets:
	@echo "Installation targets: 'updatepackages' 'clean', 'all', and 'install'"
	@echo "Developer targets: 'clean', 'fmt' and 'test'"

.PHONY: all
all:	$(commands)

cmd/trustydns-server/trustydns-server cmd/trustydns-proxy/trustydns-proxy cmd/trustydns-dig/trustydns-dig:
	$(MAKE) -C `dirname $@` all

.PHONY: race
race:
	@for dir in $(cmddirs); do echo $$dir; $(MAKE) -C $$dir $@; done

.PHONY: clean vet
clean vet:
	go $@ ./...

.PHONY: test
test:
	go $@ ./...

.PHONY: critic
critic:
	gocritic check ./...

.PHONY: fmt
fmt:
	gofmt -w `find . -name '*.go' -type f -print`

.PHONY: updatepackages
updatepackages:
	go get -u golang.org/x/net/http2
	go get -u github.com/miekg/dns
	go get -u golang.org/x/sys/unix

.PHONY: install
install: $(commands)
	install -d -o 0 -g 0 -m a=rx $(daemondest) $(cmddest)
	install -p -o 0 -g 0 -m a=rx cmd/trustydns-server/trustydns-server $(daemondest)
	install -p -o 0 -g 0 -m a=rx cmd/trustydns-proxy/trustydns-proxy $(daemondest)
	install -p -o 0 -g 0 -m a=rx cmd/trustydns-dig/trustydns-dig $(cmddest)

.PHONY: mips64
mips64: clean
	@echo 'Building for mips64 Linux targets (particularly Ubiquiti er3 and er6)'
	@GOOS=linux GOARCH=mips64 $(MAKE) all
	@file $(commands)

.PHONY: debian64
debian64: clean
	@echo 'Building for amd64 Debian (as the Debian go package is antideluvian)'
	@GOOS=linux GOARCH=amd64 $(MAKE) all
	@file $(commands)

.PHONY: pi3b
pi3b: clean
	@echo 'Building for Raspberry Pi Model B (32-bit armv71)'
	@GOOS=linux GOARCH=arm $(MAKE) all
	@file $(commands)

.PHONY: freebsd64
freebsd64: clean
	@echo Building for amd64 FreeBSD
	@GOOS=freebsd GOARCH=amd64 $(MAKE) all
	@file $(commands)
