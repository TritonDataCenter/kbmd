/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

#include <errno.h>
#include <libcustr.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/debug.h>
#include <umem.h>
#include "common.h"
#include "ecustr.h"
#include "pivy/errf.h"
#include "pivy/libssh/sshbuf.h"

/*
 * Just to be paranoid, we use a custom custr allocator that always
 * does an explicit zero before releasing memory, and use it to allocate
 * our custr_t's.
 */

static void *custr_umem_alloc(custr_alloc_t *, size_t);
static void custr_umem_free(custr_alloc_t *, void *, size_t);
static custr_alloc_ops_t custr_umem_ops = {
	.custr_ao_alloc = custr_umem_alloc,
	.custr_ao_free = custr_umem_free
};

static custr_alloc_t cu_alloc = {
	.cua_version = CUSTR_VERSION
};

static void *
custr_umem_alloc(custr_alloc_t *ca __unused, size_t len)
{
	return (umem_zalloc(len, UMEM_NOFAIL));
}

static void
custr_umem_free(custr_alloc_t *ca __unused, void *buf, size_t len)
{
	explicit_bzero(buf, len);
	umem_free(buf, len);
}

void
ecustr_init(void)
{
	VERIFY0(custr_alloc_init(&cu_alloc, &custr_umem_ops));
}

/*
 * Wrap the libcustr calls to use errf_t return values
 */
errf_t *
ecustr_alloc(custr_t **cup)
{
	custr_t *cu;

	if (custr_xalloc(&cu, &cu_alloc) != 0) {
		*cup = NULL;
		return (errfno("custr_xalloc", errno, ""));
	}

	*cup = cu;
	return (ERRF_OK);
}

errf_t *
ecustr_append(custr_t *cu, const char *s)
{
	if (custr_append(cu, s) != 0)
		return (errfno("custr_append", errno, ""));

	return (ERRF_OK);
}

errf_t *
ecustr_appendc(custr_t *cu, char c)
{
	if (custr_appendc(cu, c) != 0)
		return (errfno("custr_appendc", errno, ""));

	return (ERRF_OK);
}

errf_t *
ecustr_append_vprintf(custr_t *cu, const char *fmt, va_list ap)
{
	if (custr_append_vprintf(cu, fmt, ap) != 0)
		return (errfno("custr_append_vprintf", errno, ""));

	return (ERRF_OK);
}

errf_t *
ecustr_append_printf(custr_t *cu, const char *fmt, ...)
{
	errf_t *ret;
	va_list ap;

	va_start(ap, fmt);
	ret = ecustr_append_vprintf(cu, fmt, ap);
	va_end(ap);

	return (ret);
}

errf_t *
ecustr_append_b64(custr_t *cu, const uint8_t *bytes, size_t len)
{
	errf_t *ret = ERRF_OK;
	char *temp = NULL;
	size_t templen = ((len + 2) / 3) * 4 + 1;

	if ((ret = zalloc(templen, &temp)) != ERRF_OK) {
		return (ret);
	}

	if (b64_ntop((const u_char *)bytes, len, temp, templen) < 0) {
		ret = errf("ConversionFailure", NULL,
		    "could not convert bytes to base64");
		freezero(temp, templen);
		return (ret);
	}

	ret = ecustr_append(cu, temp);
	freezero(temp, templen);

	return (ret);
}
