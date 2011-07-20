WARNFLAGS= -Wsystem-headers -Werror -Wall -W -Wno-unused-parameter \
	-Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
	-Wold-style-definition -Wreturn-type -Wcast-qual -Wwrite-strings \
	-Wswitch -Wshadow -Wcast-align -Wunused-parameter -Wchar-subscripts \
	-Winline -Wnested-externs -Wredundant-decls

# for linux...
WARNFLAGS= -Wall

linux:
	gcc -O0 $(WARNFLAGS) -g main.c tcplay.c crc32.c safe_mem.c io.c crypto-gcrypt.c hdr.c humanize.c -o tc-play -lcrypto -ldevmapper -luuid
all:
	gcc -O0 $(WARNFLAGS) -g main.c tcplay.c crc32.c safe_mem.c io.c crypto-dev.c hdr.c humanize.c -o tc-play -lcrypto -ldevmapper -lprop -lutil
lib:
	gcc $(WARNFLAGS) -c -fPIC -O0 -Wall -g tcplay_api.c tcplay.c crc32.c safe_mem.c io.c crypto-dev.c hdr.c
	gcc -shared -Wl,-version-script=tcplay.map -o libtcplay.so tcplay_api.o tcplay.o crc32.o safe_mem.o io.o crypto-dev.o hdr.o
test:
	gcc -O0 -g -L. -I. tcplay_api_test.c -ltcplay -lcrypto -ldevmapper -lprop -lutil
clean:
	rm -f tc-play tc-play.core *.o ktrace.out
