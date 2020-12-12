ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= .

LIBSLIRP = $(BUILD_DIR)/libslirp.a
SLIRP_MAJOR_VERSION = 4
SLIRP_MINOR_VERSION = 2
SLIRP_MICRO_VERSION = 0
SLIRP_VERSION_STRING = "$(SLIRP_MAJOR_VERSION).$(SLIRP_MINOR_VERSION).$(SLIRP_MICRO_VERSION)-git"

all: $(LIBSLIRP)

SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:%.o=%.d)

INC_DIRS := $(BUILD_DIR)/src
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

override CFLAGS +=					\
	-DG_LOG_DOMAIN='"Slirp"'			\
	$(shell $(PKG_CONFIG) --cflags glib-2.0)	\
	$(INC_FLAGS)					\
	-MMD -MP
override LDFLAGS += $(shell $(PKG_CONFIG) --libs glib-2.0)

$(BUILD_DIR)/src/libslirp-version.h: Makefile
	@$(MKDIR_P) $(dir $@)
	$(call quiet-command,cat $(ROOT_DIR)/src/libslirp-version.h.in | \
		sed 's/@SLIRP_MAJOR_VERSION@/$(SLIRP_MAJOR_VERSION)/' | \
		sed 's/@SLIRP_MINOR_VERSION@/$(SLIRP_MINOR_VERSION)/' | \
		sed 's/@SLIRP_MICRO_VERSION@/$(SLIRP_MICRO_VERSION)/' | \
		sed 's/@SLIRP_VERSION_STRING@/$(SLIRP_VERSION_STRING)/' \
	> $@,"GEN","$@")

$(OBJS): $(BUILD_DIR)/src/libslirp-version.h

$(LIBSLIRP): $(OBJS)

.PHONY: clean

clean:
	rm -r $(OBJS) $(DEPS) $(LIBSLIRP) $(BUILD_DIR)/src/libslirp-version.h

$(BUILD_DIR)/src/%.o: $(ROOT_DIR)/src/%.c
	@$(MKDIR_P) $(dir $@)
	$(call quiet-command,$(CC) $(CFLAGS) -c -o $@ $<,"CC","$@")

%.a:
	$(call quiet-command,rm -f $@ && $(AR) rcs $@ $^,"AR","$@")

PKG_CONFIG ?= pkg-config
MKDIR_P ?= mkdir -p
quiet-command-run = $(if $(V),,$(if $2,printf "  %-7s %s\n" $2 $3 && ))$1
quiet-@ = $(if $(V),,@)
quiet-command = $(quiet-@)$(call quiet-command-run,$1,$2,$3)

print-%:
	@echo '$*=$($*)'

.SUFFIXES:

-include $(DEPS)
