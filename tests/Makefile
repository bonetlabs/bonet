GO      ?= go
GO_DIR  := go
BIN_DIR ?= bin
SERVER  := $(BIN_DIR)/server
CLIENT  := $(BIN_DIR)/client
SUITES  := $(patsubst %/Makefile,%,$(wildcard */Makefile))
SUITE   ?= all
RUN_ARGS ?=

GO_SOURCES := $(wildcard $(GO_DIR)/*.go $(GO_DIR)/server/*.go $(GO_DIR)/client/*.go)

all: suites $(SERVER) $(CLIENT)

suites: $(SUITES)

$(SUITES):
	$(MAKE) -C $@

$(BIN_DIR):
	mkdir -p $@

$(SERVER): $(GO_SOURCES) | $(BIN_DIR)
	cd $(GO_DIR) && $(GO) build -o ../$(SERVER) ./server/

$(CLIENT): $(GO_SOURCES) | $(BIN_DIR)
	cd $(GO_DIR) && $(GO) build -o ../$(CLIENT) ./client/

server client:
	./run_tests.sh --suite $(SUITE) $@ $(RUN_ARGS)

# Single-machine tests (need root): every global loaded on its own, and every
# global run on prepared packets.
check-local:
	$(MAKE) -C globals check
	$(MAKE) -C units check

server-% client-%:
	./run_tests.sh --suite $* $(firstword $(subst -, ,$@)) $(RUN_ARGS)

clean:
	rm -f $(SERVER) $(CLIENT)
	for suite in $(SUITES); do $(MAKE) -C $$suite clean; done

.PHONY: all suites clean server client server-% client-% check-local $(SUITES)
