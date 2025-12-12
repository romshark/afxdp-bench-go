COUNT ?= 1000000

# Interfaces (override on command line if needed)
IFACE_EGRESS  ?= center_1
IFACE_INGRESS ?= top_2

ZC ?= 0 # Set ZC=1 to enable zerocopy

TIME_CMD := /usr/bin/time -v # Use GNU time for detailed syscall/CPU stats.

define get_stat
	ethtool -S $(1) | awk -v key="$(2)" '$$1 == key":" { print $$2 }'
endef

gogenerate:
	go generate ./...

build-p2p: gogenerate
	go build -o p2p ./cmd/p2p

build-route: gogenerate
	go build -o route ./cmd/route

run-route: build-route
	@echo "---- RUNNING ROUTER BENCHMARK ----"
	sudo $(TIME_CMD) ./route -n $(COUNT)

run-p2p: build-p2p
	@echo "COUNT=$(COUNT)"
	@echo "EGRESS=$(IFACE_EGRESS)"
	@echo "INGRESS=$(IFACE_INGRESS)"
	@echo "ZEROCOPY=$(ZC)"

	@echo "---- BEFORE ----"
	$(eval TX_PHY_BEFORE := $(shell $(call get_stat,$(IFACE_EGRESS),tx_packets_phy)))
	$(eval BYTES_PHY_BEFORE := $(shell $(call get_stat,$(IFACE_EGRESS),tx_bytes_phy)))
	$(eval RX_PHY_BEFORE := $(shell $(call get_stat,$(IFACE_INGRESS),rx_packets_phy)))
	$(eval RX_BYTES_PHY_BEFORE := $(shell $(call get_stat,$(IFACE_INGRESS),rx_bytes_phy)))

	@echo "---- RUN ----"
	@if [ "$(ZC)" = "1" ]; then \
		sudo $(TIME_CMD) ./p2p -n $(COUNT) -z; \
	else \
		sudo $(TIME_CMD) ./p2p -n $(COUNT); \
	fi

	@echo "---- AFTER ----"
	$(eval TX_PHY_AFTER := $(shell $(call get_stat,$(IFACE_EGRESS),tx_packets_phy)))
	$(eval BYTES_PHY_AFTER := $(shell $(call get_stat,$(IFACE_EGRESS),tx_bytes_phy)))
	$(eval RX_PHY_AFTER := $(shell $(call get_stat,$(IFACE_INGRESS),rx_packets_phy)))
	$(eval RX_BYTES_PHY_AFTER := $(shell $(call get_stat,$(IFACE_INGRESS),rx_bytes_phy)))

	@echo "---- REPORT ----"
	@echo "Requested TX:       $(COUNT)"
	@echo "Egress ($(IFACE_EGRESS)):"
	@echo "  tx_packets_phy delta: $$(( $(TX_PHY_AFTER) - $(TX_PHY_BEFORE) ))"
	@echo "  tx_bytes_phy   delta: $$(( $(BYTES_PHY_AFTER) - $(BYTES_PHY_BEFORE) ))"
	@echo "Ingress ($(IFACE_INGRESS)):"
	@echo "  rx_packets_phy delta: $$(( $(RX_PHY_AFTER) - $(RX_PHY_BEFORE) ))"
	@echo "  rx_bytes_phy   delta: $$(( $(RX_BYTES_PHY_AFTER) - $(RX_BYTES_PHY_BEFORE) ))"

.PHONY: gogenerate build-p2p build-route run-p2p run-route
