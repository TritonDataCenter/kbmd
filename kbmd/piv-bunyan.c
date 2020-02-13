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

#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>

/*
 * The _BUNYAN_H preprocessor guards conflict between the system bunyan.h
 * and pivy/bunyan.h, so we #undef after inclusion to allow both to be used.
 */
#include <bunyan.h>
#undef _BUNYAN_H

/*
 * The pivy bunyan also defines it's own 'bunyan_init' with a different
 * function signature than the system bunyan library. We do not link in
 * the pivy bunyan.o file (this file acts as a shim between the pivy
 * bunyan API and the system bunyan API to allow the pivy objects we do
 * link in to logg).  We define the pivy bunyan_init to a non-conflicting
 * name to prevent compilation errors. None of the pivy objects linked call
 * the pivy bunyan_init(), so while gross, it works out in the end.
 */
#define	bunyan_init pivy_bunyan_init
#include "pivy/bunyan.h"
#undef bunyan_init

#include "pivy/errf.h"
#include "ecustr.h"
#include "common.h"

typedef int (*bunyan_log_f)(bunyan_logger_t *, const char *, ...);

static const char hexdigits[] = "0123456789ABCDEF";

static bunyan_log_f
getlog(enum bunyan_log_level lvl)
{
	switch (lvl) {
	case BNY_TRACE:
		return (bunyan_trace);
	case BNY_DEBUG:
		return (bunyan_debug);
	case BNY_INFO:
		return (bunyan_info);
	case BNY_WARN:
		return (bunyan_warn);
	case BNY_ERROR:
		return (bunyan_error);
	case BNY_FATAL:
		return (bunyan_fatal);
	default:
		panic("Invalid log level %d", lvl);
	}
}

void
bunyan_log(enum bunyan_log_level lvl, const char *msg, ...)
{
	errf_t *ret;
	bunyan_logger_t *plog;
	const char *name;
	custr_t *bh;
	va_list ap;

	if (bunyan_child(tlog, &plog, BUNYAN_T_END) != 0)
		return;

	if ((ret = ecustr_alloc(&bh)) != ERRF_OK) {
		errf_free(ret);
		return;
	}

	va_start(ap, msg);
	while ((name = va_arg(ap, const char *)) != NULL) {
		enum bunyan_arg_type typ = va_arg(ap, enum bunyan_arg_type);
		union {
			char *s;
			uint64_t u64;
			const uint8_t *bin;
			int i;
			uint_t ui;
			size_t sz;
			void *tv;
		} val;
		size_t bh_sz;
		int rc;

		switch (typ) {
		case BNY_STRING:
			val.s = va_arg(ap, char *);
			rc = bunyan_key_add(plog, name, BUNYAN_T_STRING, val.s,
			    BUNYAN_T_END);
			break;
		case BNY_INT:
			val.i = va_arg(ap, int);
			rc = bunyan_key_add(plog, name, BUNYAN_T_INT32, val.i,
			    BUNYAN_T_END);
			break;
		case BNY_UINT:
			val.ui = va_arg(ap, uint_t);
			rc = bunyan_key_add(plog, name, BUNYAN_T_UINT32, val.ui,
			    BUNYAN_T_END);
			break;
		case BNY_UINT64:
			val.u64 = va_arg(ap, uint64_t);
			rc = bunyan_key_add(plog, name, BUNYAN_T_UINT64,
			    val.u64, BUNYAN_T_END);
			break;
		case BNY_SIZE_T:
			val.sz = va_arg(ap, size_t);
			rc = bunyan_key_add(plog, name, BUNYAN_T_UINT64,
			    (uint64_t)val.sz, BUNYAN_T_END);
			break;
		case BNY_ERF:
			val.tv = va_arg(ap, void *);
			rc = bunyan_key_add(plog, name, BUNYAN_T_STRING,
			    errf_name(val.tv));
			break;
		case BNY_BIN_HEX:
			val.bin = va_arg(ap, const uint8_t *);
			bh_sz = va_arg(ap, size_t);
			custr_reset(bh);

			if (custr_append(bh, "<< ") != 0)
				goto done;

			for (size_t i = 0; i < bh_sz; i++) {
				const uint8_t byte = val.bin[i];

				if (i > 0 && custr_appendc(bh, ' ') != 0)
					goto done;

				if (custr_appendc(bh,
				    hexdigits[byte >> 4]) != 0 ||
				    custr_appendc(bh,
				    hexdigits[byte & 0xF]) != 0)
					goto done;
			}

			if (custr_append(bh, " >>") != 0)
				goto done;

			rc = bunyan_key_add(plog,
			    name, BUNYAN_T_STRING, custr_cstr(bh),
			    BUNYAN_T_END);
			break;

		default:
			bunyan_warn(tlog, "Unsupported piv_bunyan type",
			    BUNYAN_T_INT32, "type", (int32_t)typ,
			    BUNYAN_T_END);
			break;
		}

		if (rc != 0)
			goto done;
	}
	getlog(lvl)(plog, msg, BUNYAN_T_END);

done:
	va_end(ap);
	bunyan_fini(plog);
	custr_free(bh);
}
