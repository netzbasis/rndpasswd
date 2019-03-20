/*
 * Copyright (c) 2019 Benjamin Baier <ben@netzbasis.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXLEN		128 /* includes NUL */
#define ALPHA		(1 << 0)
#define NUM		(1 << 1)
#define SPECIAL		(1 << 2)

static int check(char, int);
static void __dead usage(void);

int
main(int argc, char *argv[])
{
	int ch;
	const char *errstr;
	size_t offset;
	char rnd[MAXLEN] = {'\0'};
	char hash[MAXLEN] = {'\0'};
	char *pref = "bcrypt,a";
	int f_rounds = 0;
	int f_chars = 0;
	int f_encrypt = 0;
	int f_repeat = 0;
	size_t f_len = 12;
	int ret = 1;

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	while ((ch = getopt(argc, argv, "ab:el:nrs")) != -1) {
		switch (ch) {
		case 'a':
			f_chars |= ALPHA;
			break;
		case 'b':
			f_rounds = strtonum(optarg, 4, 31 , &errstr);
			if (errstr != NULL)
				errx(1, "bcrypt rounds invalid: %s", errstr);
			/* FALLTHROUGH */
		case 'e':
			f_encrypt = 1;
			break;
		case 'l':
			f_len = strtonum(optarg, 1, MAXLEN - 1 , &errstr);
			if (errstr != NULL)
				errx(1, "length is %s", errstr);
			break;
		case 'n':
			f_chars |= NUM;
			break;
		case 'r':
			f_repeat = 1;
			break;
		case 's':
			f_chars |= SPECIAL;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc > 0)
		usage();

	if (f_chars == 0) {
		f_chars |= ALPHA;
		f_chars |= NUM;
		f_chars |= SPECIAL;
	}

	if (f_rounds) {
		if ((pref = calloc(16, 1)) == NULL)
			err(1, "calloc");
		if (snprintf(pref, 16, "bcrypt,%d", f_rounds) == -1)
			err(1, "snprintf");
	}

	(void)setvbuf(stdout, NULL, _IOLBF, 0);
	do {
		memset(rnd, '\0', MAXLEN);
		offset = 0;
		while (offset < f_len) {
			/* get random ascii character >=33 and <=126 */
			rnd[offset] = (char)(arc4random_uniform(127 - 33) + 33);
			if (check(rnd[offset], f_chars))
				offset++;
		}
		if (f_encrypt) {
			memset(hash, '\0', MAXLEN);
			if (crypt_newhash(rnd, pref, hash, MAXLEN - 1) != 0)
				goto fail;
		}
		if (printf("%s%s%s\n", rnd, f_encrypt ? " " : "", hash) == -1)
			goto fail;
	} while (f_repeat);

	ret = 0;
fail:
	if (f_rounds)
		free(pref);
	explicit_bzero(rnd, MAXLEN);
	explicit_bzero(hash, MAXLEN);
	return ret;
}

static int
check(char c, int flags)
{
	if (flags & ALPHA)
		if (('A' <= c && c <= 'Z') ||
		    ('a' <= c && c <= 'z'))
			return 1;

	if (flags & NUM)
		if ('0' <= c && c <= '9')
			return 1;

	if (flags & SPECIAL)
		if (strchr("!#$%&*+-?@~", c))
			return 1;

	return 0;
}

static void __dead
usage(void)
{
	fprintf(stderr, "usage: %s [-aenrs] [-b rounds] [-l length]\n",
	    getprogname());
	exit(1);
}
