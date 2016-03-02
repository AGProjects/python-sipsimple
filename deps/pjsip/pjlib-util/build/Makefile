
include ../../build.mak
include ../../version.mak
include $(PJDIR)/build/common.mak

RULES_MAK := $(PJDIR)/build/rules.mak

PJLIB_LIB:=$(PJDIR)/pjlib/lib/libpj-$(TARGET_NAME)$(LIBEXT)
export PJLIB_UTIL_LIB:=../lib/libpjlib-util-$(TARGET_NAME)$(LIBEXT)

###############################################################################
# Gather all flags.
#
export _CFLAGS 	:= $(CC_CFLAGS) $(OS_CFLAGS) $(HOST_CFLAGS) $(M_CFLAGS) \
		   $(CFLAGS) $(CC_INC)../include $(CC_INC)../../pjlib/include
export _CXXFLAGS:= $(_CFLAGS) $(CC_CXXFLAGS) $(OS_CXXFLAGS) $(M_CXXFLAGS) \
		   $(HOST_CXXFLAGS) $(CXXFLAGS)
export _LDFLAGS := $(subst /,$(HOST_PSEP),$(PJLIB_UTIL_LIB)) \
		   $(subst /,$(HOST_PSEP),$(PJLIB_LIB)) \
		   $(CC_LDFLAGS) $(OS_LDFLAGS) $(M_LDFLAGS) $(HOST_LDFLAGS) \
		   $(LDFLAGS) 

###############################################################################
# Defines for building PJLIB-UTIL library
#
export PJLIB_UTIL_SRCDIR = ../src/pjlib-util
export PJLIB_UTIL_OBJS += $(OS_OBJS) $(M_OBJS) $(CC_OBJS) $(HOST_OBJS) \
		base64.o crc32.o errno.o dns.o \
		dns_dump.o dns_server.o getopt.o hmac_md5.o hmac_sha1.o \
		http_client.o md5.o pcap.o resolver.o scanner.o sha1.o \
		srv_resolver.o string.o stun_simple.o \
		stun_simple_client.o xml.o
export PJLIB_UTIL_CFLAGS += $(_CFLAGS)

export CC_OUT CC AR RANLIB HOST_MV HOST_RM HOST_RMDIR HOST_MKDIR OBJEXT LD LDOUT 
###############################################################################
# Main entry
#
# $(TARGET) is defined in os-$(OS_NAME).mak file in current directory.
#
TARGETS := pjlib-util

all: $(TARGETS)

doc:
	cd .. && rm -rf docs/$(PJ_VERSION) && doxygen docs/doxygen.cfg
	@if [ -n "$(WWWDIR)" ] && ! [ -d "$(WWWDIR)/docs/$(PJ_VERSION)/pjlib-util/docs/html" ] ; then \
		echo "Creating docs/$(PJ_VERSION)/pjlib-util/docs/html" ; \
		mkdir -p $(WWWDIR)/docs/$(PJ_VERSION)/pjlib-util/docs/html ; \
	fi 
	@if [ -n "$(WWWDIR)" ] && [ -d "$(WWWDIR)/docs/$(PJ_VERSION)/pjlib-util/docs/html" ] ; then \
		echo "Copying docs/$(PJ_VERSION) to $(WWWDIR)/docs/$(PJ_VERSION)/pjlib-util/docs/html.." ; \
		cp -v -a ../docs/$(PJ_VERSION)/html/* $(WWWDIR)/docs/$(PJ_VERSION)/pjlib-util/docs/html/ ; \
	fi

dep: depend
distclean: realclean

.PHONY: dep depend pjlib pjlib-test clean realclean distclean

pjlib-util:
	$(MAKE) -f $(RULES_MAK) APP=PJLIB_UTIL app=pjlib-util $(PJLIB_UTIL_LIB)

.PHONY: ../lib/pjlib-util.ko
../lib/pjlib-util.ko:
	echo Making $@
	$(MAKE) -f $(RULES_MAK) APP=PJLIB_UTIL app=pjlib-util $@

clean:
	$(MAKE) -f $(RULES_MAK) APP=PJLIB_UTIL app=pjlib-util $@

realclean:
	$(subst @@,$(subst /,$(HOST_PSEP),.pjlib-util-$(TARGET_NAME).depend),$(HOST_RMR))
	$(subst @@,$(subst /,$(HOST_PSEP),.pjlib-util-test-$(TARGET_NAME).depend),$(HOST_RMR))
	$(MAKE) -f $(RULES_MAK) APP=PJLIB_UTIL app=pjlib-util $@

depend:
	$(MAKE) -f $(RULES_MAK) APP=PJLIB_UTIL app=pjlib-util $@

