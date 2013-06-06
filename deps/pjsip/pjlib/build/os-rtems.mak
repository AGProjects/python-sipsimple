#
# PJLIB OS specific configuration for RTEMS
#
# Thanks Zetron, Inc. and Phil Torre <ptorre@zetron.com> for donating PJLIB
# port to RTEMS.
#

#
# PJLIB_OBJS specified here are object files to be included in PJLIB
# (the library) for this specific operating system. Object files common 
# to all operating systems should go in Makefile instead.
#
export PJLIB_OBJS += 	addr_resolv_sock.o guid_simple.o \
			log_writer_stdout.o os_core_unix.o \
			os_error_unix.o os_time_unix.o \
			os_timestamp_common.o os_timestamp_posix.o \
			pool_policy_malloc.o sock_bsd.o sock_select.o

export PJLIB_OBJS += ioqueue_select.o 
export PJLIB_OBJS += file_access_unistd.o file_io_ansi.o

#
# TEST_OBJS are operating system specific object files to be included in
# the test application.
#
export TEST_OBJS +=	main_rtems.o

#
# RTEMS_LIBRARY_PATH points to the installed RTEMS libraries for the
# desired target.  pjlib-test can't link without this.
#
export RTEMS_LIBRARY_PATH := $(RTEMS_LIBRARY_PATH)

#
# Additional LDFLAGS for pjlib-test
#
export TEST_LDFLAGS += 

#
# TARGETS are make targets in the Makefile, to be executed for this given
# operating system.
#
export TARGETS	    =	pjlib pjlib-test



