/*
 * Copyright (c) 2011 Alex Hornung <alex@alexhornung.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/types.h>
#include <sys/diskslice.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "tc-play.h"

void *
read_to_safe_mem(const char *file, off_t offset, size_t *sz)
{
	void *mem = NULL;
	ssize_t r;
	int fd;

	if ((fd = open(file, O_RDONLY)) < 0) {
		fprintf(stderr, "Error opening file %s\n", file);
		return NULL;
	}

	if ((mem = alloc_safe_mem(*sz)) == NULL) {
		fprintf(stderr, "Error allocating memory\n");
		goto out;
	}

	if ((lseek(fd, offset, SEEK_SET) < 0)) {
		fprintf(stderr, "Error seeking on file %s\n", file);
		goto m_err;
	}

	if ((r = read(fd, mem, *sz)) <= 0) {
		fprintf(stderr, "Error reading from file %s\n", file);
		goto m_err;
	}

out:
	*sz = r;
	close(fd);
	return mem;
	/* NOT REACHED */

m_err:
	free_safe_mem(mem);
	close(fd);
	return NULL;
}

int
get_random(unsigned char *buf, size_t len)
{
	int fd;
	ssize_t r;
	size_t rd = 0;
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 }; /* 10 ms */


	if ((fd = open("/dev/random", O_RDONLY)) < 0) {
		fprintf(stderr, "Error opening /dev/random\n");
		return -1;
	}

	while (rd < len) {
		if ((r = read(fd, buf+rd, len-rd)) < 0) {
			fprintf(stderr, "Error reading from /dev/random\n");
			close(fd);
			return -1;
		}
		rd += r;
		nanosleep(&ts, NULL);
	}

	close(fd);
	return 0;
}

int
secure_erase(const char *dev, size_t bytes, size_t blksz)
{
	size_t erased = 0;
	int fd_rand, fd;
	char buf[MAX_BLKSZ];
	ssize_t r, w;

	if (blksz > MAX_BLKSZ) {
		fprintf(stderr, "blksz > MAX_BLKSZ\n");
		return -1;
	}

	if ((fd_rand = open("/dev/urandom", O_RDONLY)) < 0) {
		fprintf(stderr, "Error opening /dev/urandom\n");
		return -1;
	}

	if ((fd = open(dev, O_WRONLY)) < 0) {
		close(fd_rand);
		fprintf(stderr, "Error opening %s\n", dev);
		return -1;
	}

	while (erased < bytes) {
		if ((r = read(fd_rand, buf, blksz)) < 0) {
			fprintf(stderr, "Error reading from /dev/urandom\n");
			close(fd);
			close(fd_rand);
			return -1;
		}

		if (r < blksz)
			continue;

		if ((w = write(fd, buf, blksz)) < 0) {
			fprintf(stderr, "Error writing to %s\n", dev);
			close(fd);
			close(fd_rand);
			return -1;
		}

		erased += (size_t)w;
	}

	close(fd);
	close(fd_rand);

	return 0;
}

int
get_disk_info(const char *dev, size_t *blocks, size_t *bsize)
{
	struct partinfo pinfo;
	int fd;

	if ((fd = open(dev, O_RDONLY)) < 0) {
		fprintf(stderr, "Error opening %s\n", dev);
		return -1;
	}

	memset(&pinfo, 0, sizeof(struct partinfo));

	if (ioctl(fd, DIOCGPART, &pinfo) < 0) {
		close(fd);
		return -1;
	}

	*blocks = pinfo.media_blocks;
	*bsize = pinfo.media_blksize;

	close(fd);
	return 0;
}

int
write_mem(const char *dev, off_t offset, size_t blksz, void *mem, size_t bytes)
{
	ssize_t w;
	int fd;

	if ((fd = open(dev, O_WRONLY)) < 0) {
		fprintf(stderr, "Error opening device %s\n", dev);
		return -1;
	}

	if ((lseek(fd, offset, SEEK_SET) < 0)) {
		fprintf(stderr, "Error seeking on device %s\n", dev);
		close(fd);
		return -1;
	}

	if ((w = write(fd, mem, bytes)) <= 0) {
		fprintf(stderr, "Error writing to device %s\n", dev);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int
read_passphrase(char *prompt, char *pass, size_t passlen)
{
	struct termios termios_old, termios_new;
	ssize_t n;
	int fd, r = 0, cfd = 0;

	if ((fd = open("/dev/tty", O_RDONLY)) == -1) {
		fd = STDIN_FILENO;
		cfd = 1;
	}

	printf(prompt);
	fflush(stdout);

	memset(pass, 0, passlen);

	tcgetattr(fd, &termios_old);
	memcpy(&termios_new, &termios_old, sizeof(termios_new));
	termios_new.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSAFLUSH, &termios_new);

	n = read(fd, pass, passlen-1);
	if (n > 0) {
		pass[n-1] = '\0'; /* Strip trailing \n */
	} else {
		r = EIO;
	}

	if (cfd)
		close(fd);

	tcsetattr(fd, TCSAFLUSH, &termios_old);
	putchar('\n');

	return r;
}
