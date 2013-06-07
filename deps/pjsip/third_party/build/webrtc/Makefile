include ../../../build.mak
include ../../../build/common.mak

export LIBDIR := ../../lib

RULES_MAK := $(PJDIR)/build/rules.mak

export WEBRTCAEC_LIB := ../../lib/libwebrtcaec-$(TARGET_NAME)$(LIBEXT)

WEBRTC_DEFS := \
	-D__STDC_FORMAT_MACROS \
	-DDYNAMIC_ANNOTATIONS_ENABLED=1 \
	-D_DEBUG

WEBRTC_CFLAGS := \
	-fno-exceptions \
	-Wall \
	-Wno-unused-parameter \
	-Wno-missing-field-initializers \
	-D_FILE_OFFSET_BITS=64 \
	-fvisibility=hidden \
	-pipe \
	-fno-strict-aliasing

WEBRTC_CFLAGS_CC := \
	-fno-threadsafe-statics \
	-fvisibility-inlines-hidden \
	-Wsign-compare

WEBRTC_SRC_BASE := ../../webrtc

WEBRTCAEC_INCS := \
		   $(CC_INC)$(WEBRTC_SRC_BASE)/src \
		   $(CC_INC)$(WEBRTC_SRC_BASE)/src/common_audio/signal_processing_library/main/interface \
		   $(CC_INC)$(WEBRTC_SRC_BASE)/src/modules/audio_processing/aec/main/interface \
		   $(CC_INC)$(WEBRTC_SRC_BASE)/src/modules/audio_processing/ns/main/interface \
		   $(CC_INC)$(WEBRTC_SRC_BASE)/src/modules/audio_processing/utility \
		   $(CC_INC)$(WEBRTC_SRC_BASE)/src/system_wrappers/source/spreadsortlib \
		   $(CC_INC)$(WEBRTC_SRC_BASE)/src/system_wrappers/interface

export _CFLAGS 	:= $(CC_CFLAGS) $(OS_CFLAGS) $(HOST_CFLAGS) $(M_CFLAGS) $(CFLAGS) \
		   $(WEBRTC_DEFS) $(WEBRTC_CFLAGS) \
		   $(CC_INC). \
		   $(CC_INC)../../../pjlib/include \
		   $(WEBRTCAEC_INCS)
export _CXXFLAGS:= $(_CFLAGS) $(CC_CXXFLAGS) $(OS_CXXFLAGS) $(M_CXXFLAGS) $(HOST_CXXFLAGS) $(CXXFLAGS) \
		   $(WEBRTC_DEFS) $(WEBRTC_CFLAGS_CC)
export _LDFLAGS := $(CC_LDFLAGS) $(OS_LDFLAGS) $(M_LDFLAGS) $(HOST_LDFLAGS) \
		   $(LDFLAGS)


AEC_OBJS := modules/audio_processing/aec/main/source/echo_cancellation.o \
	    modules/audio_processing/aec/main/source/aec_core.o \
	    modules/audio_processing/aec/main/source/aec_core_sse2.o \
	    modules/audio_processing/aec/main/source/aec_rdft.o \
	    modules/audio_processing/aec/main/source/aec_rdft_sse2.o \
	    modules/audio_processing/aec/main/source/resampler.o

APM_OBJS := modules/audio_processing/utility/ring_buffer.o \
	    modules/audio_processing/utility/fft4g.o

SPL_OBJS := common_audio/signal_processing_library/main/source/auto_corr_to_refl_coef.o \
	    common_audio/signal_processing_library/main/source/auto_correlation.o \
	    common_audio/signal_processing_library/main/source/complex_fft.o \
	    common_audio/signal_processing_library/main/source/complex_ifft.o \
	    common_audio/signal_processing_library/main/source/complex_bit_reverse.o \
	    common_audio/signal_processing_library/main/source/copy_set_operations.o \
	    common_audio/signal_processing_library/main/source/cos_table.o \
	    common_audio/signal_processing_library/main/source/cross_correlation.o \
	    common_audio/signal_processing_library/main/source/division_operations.o \
	    common_audio/signal_processing_library/main/source/dot_product_with_scale.o \
	    common_audio/signal_processing_library/main/source/downsample_fast.o \
	    common_audio/signal_processing_library/main/source/energy.o \
	    common_audio/signal_processing_library/main/source/filter_ar.o \
	    common_audio/signal_processing_library/main/source/filter_ar_fast_q12.o \
	    common_audio/signal_processing_library/main/source/filter_ma_fast_q12.o \
	    common_audio/signal_processing_library/main/source/get_hanning_window.o \
	    common_audio/signal_processing_library/main/source/get_scaling_square.o \
	    common_audio/signal_processing_library/main/source/hanning_table.o \
	    common_audio/signal_processing_library/main/source/ilbc_specific_functions.o \
	    common_audio/signal_processing_library/main/source/levinson_durbin.o \
	    common_audio/signal_processing_library/main/source/lpc_to_refl_coef.o \
	    common_audio/signal_processing_library/main/source/min_max_operations.o \
	    common_audio/signal_processing_library/main/source/randn_table.o \
	    common_audio/signal_processing_library/main/source/randomization_functions.o \
	    common_audio/signal_processing_library/main/source/refl_coef_to_lpc.o \
	    common_audio/signal_processing_library/main/source/resample.o \
	    common_audio/signal_processing_library/main/source/resample_48khz.o \
	    common_audio/signal_processing_library/main/source/resample_by_2.o \
	    common_audio/signal_processing_library/main/source/resample_by_2_internal.o \
	    common_audio/signal_processing_library/main/source/resample_fractional.o \
	    common_audio/signal_processing_library/main/source/sin_table.o \
	    common_audio/signal_processing_library/main/source/sin_table_1024.o \
	    common_audio/signal_processing_library/main/source/spl_sqrt.o \
	    common_audio/signal_processing_library/main/source/spl_sqrt_floor.o \
	    common_audio/signal_processing_library/main/source/spl_version.o \
	    common_audio/signal_processing_library/main/source/splitting_filter.o \
	    common_audio/signal_processing_library/main/source/sqrt_of_one_minus_x_squared.o \
	    common_audio/signal_processing_library/main/source/vector_scaling_operations.o \
	    common_audio/signal_processing_library/main/source/webrtc_fft_t_1024_8.o \
	    common_audio/signal_processing_library/main/source/webrtc_fft_t_rad.o

SWR_OBJS := system_wrappers/source/aligned_malloc.o \
            system_wrappers/source/atomic32.o \
            system_wrappers/source/condition_variable.o \
            system_wrappers/source/cpu.o \
            system_wrappers/source/cpu_features.o \
            system_wrappers/source/critical_section.o \
            system_wrappers/source/event.o \
            system_wrappers/source/file_impl.o \
            system_wrappers/source/list_no_stl.o \
            system_wrappers/source/map.o \
            system_wrappers/source/rw_lock.o \
            system_wrappers/source/sort.o \
            system_wrappers/source/thread.o \
            system_wrappers/source/trace_impl.o

NSX_OBJS := modules/audio_processing/ns/main/source/noise_suppression.o \
	    modules/audio_processing/ns/main/source/ns_core.o

export WEBRTCAEC_SRCDIR = $(WEBRTC_SRC_BASE)/src
export WEBRTCAEC_OBJS = $(AEC_OBJS) $(NSX_OBJS) $(APM_OBJS) $(SWR_OBJS) $(SPL_OBJS)
export WEBRTCAEC_CFLAGS = $(_CFLAGS)
export WEBRTCAEC_CXXFLAGS = $(_CXXFLAGS)

export CC_OUT CC AR RANLIB HOST_MV HOST_RM HOST_RMDIR HOST_MKDIR OBJEXT LD LDOUT


###############################################################################
# Main entry
#
# $(TARGET) is defined in os-$(OS_NAME).mak file in current directory.
#
TARGETS := libwebrtcaec

all: $(TARGETS)

doc:
	cd .. && doxygen docs/doxygen.cfg

dep: depend
distclean: realclean

.PHONY: dep depend libwebrtcaec clean realclean distclean

libwebrtcaec:
	$(MAKE) -f $(RULES_MAK) APP=WEBRTCAEC app=libwebrtcaec $(WEBRTCAEC_LIB)

clean print_lib:
	$(MAKE) -f $(RULES_MAK) APP=WEBRTCAEC app=libwebrtcaec $@

realclean:
	$(subst @@,$(subst /,$(HOST_PSEP),.ilbc-$(TARGET_NAME).depend),$(HOST_RMR))
	$(MAKE) -f $(RULES_MAK) APP=WEBRTCAEC app=libwebrtcaec $@

depend:
	$(MAKE) -f $(RULES_MAK) APP=WEBRTCAEC app=libwebrtcaec $@


