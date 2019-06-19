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
 * Copyright 2019 Joyent, Inc.
 */

#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include "ecustr.h"
#include "pivy/bunyan.h"
#include "pivy/errf.h"

void panic(const char *, ...) __NORETURN;

/*
 * This is a temporary shim to allow the pivy code to use the illumos
 * bunyan library.  Eventually we'll adapt both to use the same API, but
 * for now, we just translate.
 */

typedef enum bunyan_type {
        BUNYAN_T_END    = 0x0,
        BUNYAN_T_STRING,
        BUNYAN_T_POINTER,
        BUNYAN_T_IP,
        BUNYAN_T_IP6,
        BUNYAN_T_BOOLEAN,
        BUNYAN_T_INT32,
        BUNYAN_T_INT64,
        BUNYAN_T_UINT32,
        BUNYAN_T_UINT64,
        BUNYAN_T_DOUBLE,
        BUNYAN_T_INT64STR,
        BUNYAN_T_UINT64STR
} bunyan_type_t;

typedef struct bunyan_logger bunyan_logger_t;

extern __thread bunyan_logger_t *tlog;

extern int bunyan_trace(bunyan_logger_t *, const char *msg, ...);
extern int bunyan_debug(bunyan_logger_t *, const char *msg, ...);
extern int bunyan_info(bunyan_logger_t *, const char *msg, ...);
extern int bunyan_warn(bunyan_logger_t *, const char *msg, ...);
extern int bunyan_error(bunyan_logger_t *, const char *msg, ...);
extern int bunyan_fatal(bunyan_logger_t *, const char *msg, ...);

extern int bunyan_key_add(bunyan_logger_t *, ...);
extern int bunyan_child(const bunyan_logger_t *, bunyan_logger_t **, ...);
extern void bunyan_fini(bunyan_logger_t *);

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

				if (custr_appendc(bh, hexdigits[i >> 4]) != 0 ||
				    custr_appendc(bh, hexdigits[i & 0xF]) != 0)
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
