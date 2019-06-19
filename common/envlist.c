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
 * Copyright 2019, Joyent, Inc.
 */

#include <errno.h>
#include <libnvpair.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/debug.h>
#include <umem.h>
#include "envlist.h"
#include "pivy/errf.h"

/*
 * Just to be paranoid, we use a custom nvlist allocator that always
 * does an explicit zero before releasing memory, and use it to allocate
 * our custr_t's.
 */

static void *nv_umem_alloc(nv_alloc_t *, size_t);
static void nv_umem_free(nv_alloc_t *, void *, size_t);
static nv_alloc_ops_t nv_umem_ops = {
	.nv_ao_alloc = nv_umem_alloc,
	.nv_ao_free = nv_umem_free,
};
static nv_alloc_t nvu_alloc;

static void *
nv_umem_alloc(nv_alloc_t *nva __unused, size_t sz)
{
	return (umem_zalloc(sz, UMEM_NOFAIL));
}

static void
nv_umem_free(nv_alloc_t *nva __unused, void *buf, size_t sz)
{
	if (buf == NULL)
		return;

	/*
	 * Some of the nvlists can contain sensitive data, so always
	 * clear out the memory before returning it.
	 */
	explicit_bzero(buf, sz);
	umem_free(buf, sz);
}

void
envlist_init(void)
{
	VERIFY0(nv_alloc_init(&nvu_alloc, &nv_umem_ops));
}

/*
 * Wrap the libnvpair calls we use to use errf_t return values
 */
errf_t *
envlist_alloc(nvlist_t **nvlp)
{
	nvlist_t *nvl;
	int rc;

	rc = nvlist_xalloc(&nvl, NV_UNIQUE_NAME, &nvu_alloc);
	if (rc != 0) {
		*nvlp = NULL;
		return (errfno("nvlist_xalloc", rc, ""));
	}

	*nvlp = nvl;
	return (ERRF_OK);
}

#define	NVERR(_rc, _fn) ((_rc) == 0) ? ERRF_OK : errfno(_fn, (_rc), "")

errf_t *
envlist_pack(nvlist_t *nvl, char **bufp, size_t *buflenp)
{
	int rc = nvlist_xpack(nvl, bufp, buflenp, NV_ENCODE_NATIVE, &nvu_alloc);
	return (NVERR(rc, "nvlist_xpack"));
}

errf_t *
envlist_unpack(char *buf, size_t buflen, nvlist_t **nvlp)
{
	int rc = nvlist_xunpack(buf, buflen, nvlp, &nvu_alloc);
	return (NVERR(rc, "nvlist_xunpack"));
}

errf_t *
envlist_add_string(nvlist_t *nvl, const char *name, const char *val)
{
	int ret = nvlist_add_string(nvl, name, val);
	return (NVERR(ret, "nvlist_add_string"));
}

errf_t *
envlist_add_boolean(nvlist_t *nvl, const char *name)
{
	int ret = nvlist_add_boolean(nvl, name);
	return (NVERR(ret, "nvlist_add_boolean"));
}

errf_t *
envlist_add_boolean_value(nvlist_t *nvl, const char *name, boolean_t val)
{
	int ret = nvlist_add_boolean_value(nvl, name, val);
	return (NVERR(ret, "nvlist_add_boolean_value"));
}

errf_t *
envlist_add_int32(nvlist_t *nvl, const char *name, int32_t val)
{
	int ret = nvlist_add_int32(nvl, name, val);
	return (NVERR(ret, "nvlsit_add_int32"));
}

errf_t *
envlist_add_uint32(nvlist_t *nvl, const char *name, uint32_t val)
{
	int ret = nvlist_add_uint32(nvl, name, val);
	return (NVERR(ret, "nvlsit_add_uint32"));
}

errf_t *
envlist_add_uint8_array(nvlist_t *nvl, const char *name, const uint8_t *val,
    uint_t len)
{
	int ret = nvlist_add_uint8_array(nvl, name, (uint8_t *)val, len);
	return (NVERR(ret, "nvlist_add_uint8_array"));
}

errf_t *
envlist_add_nvlist(nvlist_t *nvl, const char *name, const nvlist_t *toadd)
{
	int ret = nvlist_add_nvlist(nvl, name, (nvlist_t *)toadd);
	return (NVERR(ret, "nvlist_add_nvlist"));
}

errf_t *
envlist_add_nvlist_array(nvlist_t *nvl, const char *name, nvlist_t * const *val,
    uint_t len)
{
	int ret = nvlist_add_nvlist_array(nvl, name, (nvlist_t **)val, len);
	return (NVERR(ret, "nvlist_add_uint8_array"));
}

errf_t *
envlist_add_string_array(nvlist_t *nvl, const char *name, char * const *val,
    uint_t nelem)
{
	int ret = nvlist_add_string_array(nvl, name, val, nelem);
	return (NVERR(ret, "nvlist_add_string_array"));
}

errf_t *
envlist_lookup_int32(nvlist_t *nvl, const char *name, int32_t *valp)
{
	int ret = nvlist_lookup_int32(nvl, name, valp);
	return (NVERR(ret, "nvlist_lookup_int32"));
}

errf_t *
envlist_lookup_uint32(nvlist_t *nvl, const char *name, uint32_t *valp)
{
	int ret = nvlist_lookup_uint32(nvl, name, valp);
	return (NVERR(ret, "nvlist_lookup_uint32"));
}

errf_t *
envlist_lookup_string(nvlist_t *nvl, const char *name, char **valp)
{
	int ret = nvlist_lookup_string(nvl, name, valp);
	return (NVERR(ret, "nvlist_lookup_string"));
}

errf_t *
envlist_lookup_nvlist(nvlist_t *nvl, const char *name, nvlist_t **valp)
{
	int ret = nvlist_lookup_nvlist(nvl, name, valp);
	return (NVERR(ret, "nvlist_lookup_nvlist"));
}

errf_t *
envlist_lookup_nvlist_array(nvlist_t *nvl, const char *name, nvlist_t ***valp,
    uint_t *lenp)
{
	int ret = nvlist_lookup_nvlist_array(nvl, name, valp, lenp);
	return (NVERR(ret, "nvlist_lookup_nvlist_array"));
}

errf_t *
envlist_lookup_uint8_array(nvlist_t *nvl, const char *name, uint8_t **valp,
    uint_t *lenp)
{
	int ret = nvlist_lookup_uint8_array(nvl, name, valp, lenp);
	return (NVERR(ret, "nvlist_lookup_uint8_array"));
}

errf_t *
envlist_lookup_string_array(nvlist_t *nvl, const char *name, char ***sarp,
    uint_t *lenp)
{
	int ret = nvlist_lookup_string_array(nvl, name, sarp, lenp);
	return (NVERR(ret, "nvlist_lookup_string_array"));
}

errf_t *
envlist_dump_json(nvlist_t *nvl, char **bufp)
{
	int ret = nvlist_dump_json(nvl, bufp);
	return (NVERR(ret, "nvlist_dump_json"));
}
