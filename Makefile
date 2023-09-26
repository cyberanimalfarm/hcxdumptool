PRODUCTION		:= 0
PRODUCTION_VERSION	:= 6.3.1
PRODUCTION_YEAR		:= 2023

VERSION_YEAR		:= $(shell echo $(PRODUCTION_YEAR))
VERSION_TAG		:= $(PRODUCTION_VERSION)

PREFIX		?= /usr
BINDIR		= $(DESTDIR)$(PREFIX)/bin

HOSTOS		:= $(shell uname -s)

CC		?= gcc
CFLAGS		?= -O3 -Wall -Wextra -Wpedantic
CFLAGS		+= -std=gnu99 -fPIC --shared
#CFLAGS		+= -ggdb -fsanitize=address
DEFS		= -DVERSION_TAG=\"$(VERSION_TAG)\" -DVERSION_YEAR=\"$(VERSION_YEAR)\"

INSTALL		?= install
INSTFLAGS	=

ifeq ($(HOSTOS), Linux)
INSTFLAGS += -D
endif


TOOLS=hcxdumptool

.PHONY: all build install clean uninstall

all: build

build: $(TOOLS)

# $1: tool name
define tool-build
$(1)_src ?= $(1).c
$(1)_libs ?=
$(1)_cflags ?=

$(1): $$($(1)_src)
	$$(CC) $$(CFLAGS) $$($(1)_cflags) $$(CPPFLAGS) -o $$@.so $$($(1)_src) $$(DEFS)

.deps/$(1).d: $(1)

.PHONY: $(1).install
$(1).install: $(1)
	$$(INSTALL) $$(INSTFLAGS) -m 0755 $(1) $$(BINDIR)/$(1)

.PHONY: $(1).clean
$(1).clean:
	rm -f .deps/$(1).d
	rm -f $(1)

.PHONY: $(1).uninstall
$(1).uninstall:
	rm -rf $$(BINDIR)/$(1)

endef

$(foreach tool,$(TOOLS),$(eval $(call tool-build,$(tool))))

install: $(patsubst %,%.install,$(TOOLS))

clean: $(patsubst %,%.clean,$(TOOLS))
	rm -rf .deps
	rm -f *.o *~

uninstall: $(patsubst %,%.uninstall,$(TOOLS))

-include .deps/*.d
