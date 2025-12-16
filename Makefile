COUNT ?= 1000000 # Sender packet target.
RATE ?= -1 # Sender rate limit.

# Interfaces (override on command line if needed)
IFACE_EGRESS  ?= center_1
IFACE_INGRESS ?= top_2

MODE ?= "" # copy/zerocopy

TIME_CMD := /usr/bin/time -v # Use GNU time for detailed syscall/CPU stats.

gogenerate:
	go generate ./...

build-p2p: gogenerate
	go build -o p2p ./cmd/p2p

build-route: gogenerate
	go build -o route ./cmd/route

run-route: build-route
	sudo $(TIME_CMD) ./route -r $(RATE) -n $(COUNT) -m $(MODE);

run-p2p: build-p2p
	sudo $(TIME_CMD) ./p2p -r $(RATE) -n $(COUNT) -m $(MODE);

.PHONY: gogenerate build-p2p build-route run-p2p run-route
