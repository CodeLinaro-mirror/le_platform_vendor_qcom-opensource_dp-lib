DESTDIR ?=
$(info "DESTDIR=$(DESTDIR)")

CROSS_COMPILE ?=
$(info "CROSS_COMPILE=$(CROSS_COMPILE)")

CC=$(CROSS_COMPILE)gcc

PRODUCT := dp_ping

DEPFLAGS = -MT $@ -MMD -MP -MF $*.tempd
MVDEP = mv -f $*.tempd $*.d && touch $@

# Detect target architecture from compiler, not build host
ARCH := $(shell $(CC) -dumpmachine | cut -d- -f1)
ifeq ($(ARCH),)
    ARCH := $(shell uname -m)
endif
$(info ARCH=$(ARCH))

CFLAGS += -Wall -Wextra -I../../include
LDFLAGS := -L/usr/local/lib -L../../ -lcsm_dp -lpthread -lrt -lbsd
ifeq ($(ARCH),x86_64)
    CFLAGS += -mcmodel=large
    LDFLAGS += -mcmodel=large
endif

ifeq ($(ARCH),aarch64)
    CFLAGS += -Wno-address-of-packed-member
endif

SRCDIRS = src

VPATH = $(foreach dir, $(SRCDIRS), $(dir))
CFILES := $(foreach dir, $(SRCDIRS), $(wildcard $(dir)/*.c))

OBJS := $(patsubst %.c,   %.o, $(notdir $(CFILES)))
DEPS := $(OBJS:.o=.d)

.PHONY: all install
all: $(PRODUCT)

clean:
	@rm -f $(OBJS) $(DEPS) $(PRODUCT)

install: $(PRODUCT)
	@install $(PRODUCT) $(DESTDIR)/usr/local/bin

$(PRODUCT): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

-include $(DEPS)

%.o : %.c
%.o : %.c %.d
	$(CC) $(DEPFLAGS) $(CFLAGS) $(CINCLUDE) -c $< -o $@
	@$(MVDEP)

%.d: ;

.PRECIOUS: %.d
