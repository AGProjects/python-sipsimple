include ../../../build.mak
include ../../../build/common.mak

export LIBDIR := ../../lib

RULES_MAK := $(PJDIR)/build/rules.mak

export OPUS_LIB := ../../lib/libopuscodec-$(TARGET_NAME)$(LIBEXT)

###############################################################################
# Gather all flags.
#
OPUS_DEFS := \
	-DOPUS_BUILD \
	-DHAVE_LRINT \
	-DVAR_ARRAYS

OPUS_SRC_BASE := ../../opus

include $(OPUS_SRC_BASE)/silk_sources.mk
include $(OPUS_SRC_BASE)/celt_sources.mk
include $(OPUS_SRC_BASE)/opus_sources.mk

OPUS_INCS := \
		   $(CC_INC)$(OPUS_SRC_BASE)/include \
		   $(CC_INC)$(OPUS_SRC_BASE)/celt \
		   $(CC_INC)$(OPUS_SRC_BASE)/silk \
		   $(CC_INC)$(OPUS_SRC_BASE)/silk/float

export _CFLAGS 	:= $(CC_CFLAGS) $(OS_CFLAGS) $(HOST_CFLAGS) $(M_CFLAGS) \
	           $(OPUS_DEFS) \
		   $(CFLAGS) $(CC_INC). \
		   $(CC_INC)../../../pjlib/include \
		   $(OPUS_INCS)
export _CXXFLAGS:= $(_CFLAGS) $(CC_CXXFLAGS) $(OS_CXXFLAGS) $(M_CXXFLAGS) \
		   $(HOST_CXXFLAGS) $(CXXFLAGS)
export _LDFLAGS := $(CC_LDFLAGS) $(OS_LDFLAGS) $(M_LDFLAGS) $(HOST_LDFLAGS) \
		   $(LDFLAGS)

OPUS_SRCS_C = $(SILK_SOURCES) $(SILK_SOURCES_FLOAT) $(CELT_SOURCES) $(OPUS_SOURCES) $(OPUS_SOURCES_FLOAT)

export OPUS_SRCDIR = $(OPUS_SRC_BASE)
export OPUS_OBJS := $(patsubst %.c,%.o,$(OPUS_SRCS_C))
export OPUS_CFLAGS = $(_CFLAGS)
export OPUS_CXXFLAGS = $(_CXXFLAGS)


export CC_OUT CC AR RANLIB HOST_MV HOST_RM HOST_RMDIR HOST_MKDIR OBJEXT LD LDOUT
###############################################################################
# Main entry
#
# $(TARGET) is defined in os-$(OS_NAME).mak file in current directory.
#
TARGETS := libopuscodec

all: $(TARGETS)

doc:
	cd .. && doxygen docs/doxygen.cfg

dep: depend
distclean: realclean

.PHONY: dep depend libopuscodec clean realclean distclean

libopuscodec:
	$(MAKE) -f $(RULES_MAK) APP=OPUS app=libopuscodec $(OPUS_LIB)

clean print_lib:
	$(MAKE) -f $(RULES_MAK) APP=OPUS app=libopuscodec $@

realclean:
	$(subst @@,$(subst /,$(HOST_PSEP),.opus-$(TARGET_NAME).depend),$(HOST_RMR))
	$(MAKE) -f $(RULES_MAK) APP=OPUS app=libopuscodec $@

depend:
	$(MAKE) -f $(RULES_MAK) APP=OPUS app=libopuscodec $@

