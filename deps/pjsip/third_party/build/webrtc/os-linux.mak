
export CFLAGS += -DWEBRTC_TARGET_PC -DWEBRTC_LINUX -DWEBRTC_THREAD_RR
export CFLAGS += -pthread

export WEBRTCAEC_OBJS += system_wrappers/source/condition_variable_posix.o \
            		 system_wrappers/source/critical_section_posix.o \
            		 system_wrappers/source/event_posix.o \
            		 system_wrappers/source/rw_lock_posix.o \
            		 system_wrappers/source/thread_posix.o \
            		 system_wrappers/source/trace_posix.o \
            		 system_wrappers/source/cpu_linux.o

