WARNFLAGS= -Wsystem-headers -Werror -Wall -W -Wno-unused-parameter \
	-Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
	-Wold-style-definition -Wreturn-type -Wcast-qual -Wwrite-strings \
	-Wswitch -Wshadow -Wcast-align -Wunused-parameter -Wchar-subscripts \
	-Winline -Wnested-externs -Wredundant-decls

all:
	gcc -O0 $(WARNFLAGS) -g tc-play.c crc32.c safe_mem.c io.c crypto.c hdr.c openssl/openssl/libcrypto.a -o tc-play -ldevmapper -lprop -lutil
experimental:
	gcc -O0 $(WARNFLAGS) -g main.c tc-play.c crc32.c safe_mem.c io.c crypto-dev.c hdr.c openssl/openssl/libcrypto.a -o tc-play -ldevmapper -lprop -lutil
lib:
	gcc $(WARNFLAGS) -c -fPIC -O0 -Wall -g tc-play-api.c tc-play.c crc32.c safe_mem.c io.c crypto-dev.c hdr.c
	gcc -shared -Wl -o libtcplay.so tc-play-api.o tc-play.o crc32.o safe_mem.o io.o crypto-dev.o hdr.o
clean:
	rm -f tc-play tc-play.core *.o ktrace.out
