CROSS_COMPILE ?=
$(info "CROSS_COMPILE=$(CROSS_COMPILE)")

UNAME_P := $(shell uname -p)
ifeq ($(UNAME_P),x86_64)
	ARCH = x86_64
endif
$(info "ARCH=$(ARCH)")

CC=$(CROSS_COMPILE)gcc

LIB = libcsm_dp.so
INSTALL = install
MVDEP = mv -f $*.tempd $*.d && touch $@

ifeq ("$(ARCH)", "")
CINCLUDE_ARCH = -I./include/arch/arm64
else
CINCLUDE_ARCH = -I./include/arch/$(ARCH)
endif

# FLAGS
CFLAGS +=-Wall -Wextra -fPIC -lpthread
CINCLUDE += -I./include -I/usr/include
CINCLUDE += $(CINCLUDE_ARCH)
LDFLAGS := -shared
DEPFLAGS = -MT $@ -MMD -MP -MF $*.tempd

# TARGETS
SRCDIRS = src
VPATH = $(foreach dir, $(SRCDIRS), $(dir))
CFILES := $(foreach dir, $(SRCDIRS), $(wildcard $(dir)/*.c))

API_FILE = csm_dp_api.h

OBJS := $(patsubst %.c,   %.o, $(notdir $(CFILES)))
DEPS := $(OBJS:.o=.d)

# RULES
$(LIB): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,$@ -o $@ $(OBJS)

%.o : %.c
%.o : %.c %.d
	$(CC) $(DEPFLAGS) $(CFLAGS) $(CINCLUDE) -c $< -o $@
	@$(MVDEP)

%.d: ;


all: $(LIB)

install: all
	$(INSTALL) $(LIB) /usr/lib64/
	$(INSTALL) include/$(API_FILE) /usr/include/

.PHONY: install clean

clean:
	rm -rf $(OBJS) $(LIB)

.PRECIOUS: %.d

-include $(DEPS)
