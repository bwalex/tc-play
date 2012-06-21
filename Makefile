# either linux or dragonfly
SYSTEM?=linux

# either openssl or gcrypt
PBKDF_BACKEND?=openssl

# system compiler, normally gcc
CC?=gcc

RM?=rm -f

# whether to enable debugging or not
DEBUG?=no

WARNFLAGS= -Wsystem-headers -Werror -Wall -W -Wno-unused-parameter \
	-Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
	-Wold-style-definition -Wreturn-type -Wcast-qual -Wwrite-strings \
	-Wswitch -Wshadow -Wcast-align -Wunused-parameter -Wchar-subscripts \
	-Winline -Wnested-externs

SRCS=	tcplay.c crc32.c safe_mem.c io.c hdr.c humanize.c
SRCS+=	crypto.c generic_xts.c
OBJS=	tcplay.o crc32.o safe_mem.o io.o hdr.o humanize.o
OBJS+=	crypto.o generic_xts.o

CFLAGS+= $(WARNFLAGS)

ifeq (${DEBUG}, yes)
  CFLAGS+= -O0 -g -DDEBUG
else
  CFLAGS+= -O3
endif

ifeq (${SYSTEM}, linux)
  CFLAGS+=	-D_GNU_SOURCE
  LIBS+=	-lgcrypt -ldevmapper -luuid
  SRCS+=	crypto-gcrypt.c
  OBJS+=	crypto-gcrypt.o
  ifeq (${PBKDF_BACKEND}, gcrypt)
    SRCS+=	pbkdf2-gcrypt.c
    OBJS+=	pbkdf2-gcrypt.o
  endif
  ifeq (${PBKDF_BACKEND}, openssl)
    SRCS+=	pbkdf2-openssl.c
    OBJS+=	pbkdf2-openssl.o
    LIBS+=	-lcrypto
  endif
endif

ifeq (${SYSTEM}, dragonfly)
  LIBS+=	-lcrypto -ldm -lprop
  SRCS+=	crypto-dev.c
  OBJS+=	crypto-dev.o
  SRCS+=	pbkdf2-openssl.c
  OBJS+=	pbkdf2-openssl.o
endif

program:
	$(CC) $(CFLAGS) -o tcplay main.c $(SRCS) $(LIBS)
lib:
	$(CC) $(CFLAGS) -c -fPIC tcplay_api.c $(SRCS)
	$(CC) -shared -Wl,-version-script=tcplay.map -o libtcplay.so tcplay_api.o $(OBJS)

test:
	$(CC) -O0 -g -L. -I. tcplay_api_test.c -ltcplay -lcrypto -ldm -lprop
clean:
	$(RM) tcplay libtcplay.so tcplay.core *.o ktrace.out

