
ACLOCAL_AMFLAGS = -I m4

if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example.conf m4/gnulib-cache.m4 linux-usb-cgminer \
		  ADL_SDK/readme.txt api-example.php miner.php	\
		  API.class API.java api-example.c windows-build.txt \
		  bitstreams/* API-README FPGA-README SCRYPT-README \
		  bitforce-firmware-flash.c

SUBDIRS		= lib compat ccan

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= cgminer

if HAS_OPENCL
bin_SCRIPTS	= *.cl
endif

cgminer_LDFLAGS	= $(PTHREAD_FLAGS)
cgminer_LDADD	= $(DLOPEN_FLAGS) @LIBCURL_LIBS@ @JANSSON_LIBS@ @PTHREAD_LIBS@ \
		  @OPENCL_LIBS@ @NCURSES_LIBS@ @PDCURSES_LIBS@ @WS2_LIBS@ \
		  @UDEV_LIBS@ @LIBUSB_LIBS@ \
		  @MATH_LIBS@ lib/libgnu.a ccan/libccan.a

if HAVE_WINDOWS
cgminer_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib @OPENCL_FLAGS@ @LIBUSB_CFLAGS@
else
cgminer_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib @OPENCL_FLAGS@ @LIBUSB_CFLAGS@ @LIBCURL_CFLAGS@
endif

# common sources
cgminer_SOURCES := cgminer.c

cgminer_SOURCES	+= elist.h miner.h compat.h bench_block.h	\
		   util.c util.h uthash.h logging.h		\
		   sha2.c sha2.h api.c usbutils.h

cgminer_SOURCES	+= logging.c

# GPU sources, TODO: make them selectable
# the GPU portion extracted from original main.c
if HAS_OPENCL
cgminer_SOURCES += driver-opencl.h driver-opencl.c

# the original GPU related sources, unchanged
cgminer_SOURCES += ocl.c ocl.h findnonce.c findnonce.h
cgminer_SOURCES += adl.c adl.h adl_functions.h
cgminer_SOURCES += *.cl
endif

if HAS_SCRYPT
cgminer_SOURCES += scrypt.c scrypt.h
endif

if HAS_CPUMINE
# original CPU related sources, unchanged
cgminer_SOURCES	+= \
		  sha256_generic.c crypto_scrypt-ref.c crypto_scrypt.h \
		  scrypt_platform.h sha256.c sha256.h sysendian.h


# the CPU portion extracted from original main.c
cgminer_SOURCES += driver-cpu.h driver-cpu.c

endif # HAS_CPUMINE

if NEED_FPGAUTILS
cgminer_SOURCES += fpgautils.c fpgautils.h
endif

if HAS_BITFORCE
cgminer_SOURCES += driver-bitforce.c
endif

if HAS_ICARUS
cgminer_SOURCES += driver-icarus.c
endif

if HAS_MODMINER
cgminer_SOURCES += driver-modminer.c usbutils.c
bitstreamsdir = $(bindir)/bitstreams
dist_bitstreams_DATA = bitstreams/*
endif

if HAS_ZTEX
cgminer_SOURCES += driver-ztex.c libztex.c libztex.h
bitstreamsdir = $(bindir)/bitstreams
dist_bitstreams_DATA = bitstreams/*
endif
