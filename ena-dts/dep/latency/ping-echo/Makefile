# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

APP = ping-echo
SRCS-y := ping-echo.c

# Try to build using pkg-config as a standalone app at first
ifeq ($(shell pkg-config --exists libdpdk && echo 0), 0)

PKGCONF ?= pkg-config

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
CFLAGS += -DALLOW_EXPERIMENTAL_API

LDFLAGS += $(shell $(PKGCONF) --libs libdpdk)

all: $(SRCS-y) Makefile $(PC_FILE)
	$(CC) $(CFLAGS) $(SRCS-y) -o $(APP) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f build/$(APP)
	test -d build && rmdir -p build || true

else # Build using legacy build system

include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += -O3
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.app.mk
endif
