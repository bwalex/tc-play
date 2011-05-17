all:
	gcc -O0 -Wall -g tc-play.c crc32.c safe_mem.c io.c crypto.c hdr.c openssl/openssl/libcrypto.a -o tc-play -ldevmapper -lprop -lutil
clean:
	rm -f tc-play tc-play.core *.o ktrace.out
