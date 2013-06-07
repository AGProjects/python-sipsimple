
export CFLAGS += -DWEBRTC_TARGET_PC -D_WIN32 -D_CRT_SECURE_NO_DEPRECATE -D_SCL_SECURE_NO_DEPRECATE -D__STD_C

export WEBRTCAEC_OBJS += system_wrappers/source/condition_variable_windows.o \
            		 system_wrappers/source/critical_section_windows.o \
            		 system_wrappers/source/event_windows.o \
            		 system_wrappers/source/rw_lock_windows.o \
            		 system_wrappers/source/thread_windows.o \
            		 system_wrappers/source/trace_windows.o \
            		 system_wrappers/source/cpu_windows.o

