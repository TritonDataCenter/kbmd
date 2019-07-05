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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <port.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <sys/refhash.h>
#include <sys/types.h>
#include "common.h"
#include "kbmd.h"
#include "pivy/errf.h"

typedef struct kbm_event {
	refhash_link_t	ke_link;
	int		ke_fd;
	pid_t		ke_pid;
	void		(*ke_cb)(pid_t, void *);
	void		*ke_arg;
} kbm_event_t;

/* Arbitrary prime, sorry */
#define	BUCKET_COUNT 17

static int evport = -1;
static mutex_t ev_lock = ERRORCHECKMUTEX;
static refhash_t *ev_hash;

thread_t event_tid;
extern volatile boolean_t kbmd_quit;

static uint64_t
event_hash(const void *tp)
{
	const pid_t pid = *(const pid_t *)tp;
	return ((uint64_t)pid);
}

static int
event_cmp(const void *ta, const void *tb)
{
	const pid_t *pida = ta;
	const pid_t *pidb = tb;

	if (*pida < *pidb) {
		return (-1);
	}
	if (*pida > *pidb) {
		return (1);
	}
	return (0);
}

static void
event_free(void *ep)
{
	if (ep == NULL) {
		return;
	}

	free(ep);
}

/*
 * This is _extremely_ rough.  Once the ccid port event design is better
 * flushed out, as well as the gossip protocol requirements, this will
 * be expanded into something a bit more generic.  We'll also likely employ
 * finer-grained locking and probably refhashes to track events.
 */
errf_t *
kbmd_watch_pid(pid_t pid, void (*cb)(pid_t, void *), void *arg)
{
	errf_t *ret;
	kbm_event_t *evt;
	char path[PATH_MAX];

	if ((ret = zalloc(sizeof (*evt), &evt)) != ERRF_OK)
		return (ret);

	(void) snprintf(path, sizeof (path), "/proc/%d/psinfo", pid);
	if ((evt->ke_fd = open(path, O_RDONLY)) == -1) {
		ret = errfno("open", errno,
		    "cannot open psinfo file for pid %d", pid);
		free(evt);
		return (ret);
	}

	evt->ke_pid = pid;
	evt->ke_cb = cb;
	evt->ke_arg = arg;

	mutex_enter(&ev_lock);
	if (port_associate(evport, PORT_SOURCE_FD, (uintptr_t)evt->ke_fd,
	    POLLPRI, evt) < 0) {
		ret = errfno("port_associate", errno,
		    "cannot create port event for pid %d psinfo", pid);
		mutex_exit(&ev_lock);
		event_free(evt);
		return (ret);
	}
	refhash_insert(ev_hash, evt);

	/* hold for event port */
	refhash_hold(ev_hash, evt);
	mutex_exit(&ev_lock);

	return (ERRF_OK);
}

errf_t *
kbmd_unwatch_pid(pid_t pid)
{
	kbm_event_t *evt;
	int rc;

	mutex_enter(&ev_lock);

	evt = refhash_lookup(ev_hash, &pid);
	if (evt == NULL) {
		mutex_exit(&ev_lock);
		return (errf("NotFoundError", NULL,
		    "tried to stop already unwatched pid %d", pid));
	}

	rc = port_dissociate(evport, PORT_SOURCE_FD, (uintptr_t)evt->ke_pid);
	if (rc == 0) {
		refhash_rele(ev_hash, evt);
	}

	refhash_remove(ev_hash, evt);
	mutex_exit(&ev_lock);
	return (ERRF_OK);
}

static void
fd_event(kbm_event_t *ke, int pevents)
{
	mutex_enter(&ev_lock);
	if (!refhash_obj_valid(ev_hash, ke)) {
		mutex_exit(&ev_lock);
		return;
	}

	/* process exited/died */
	if ((pevents & POLLHUP) != 0) {
		/* we still have the event port hold at this point */
		refhash_remove(ev_hash, ke);
		mutex_exit(&ev_lock);

		ke->ke_cb(ke->ke_pid, ke->ke_arg);

		mutex_enter(&ev_lock);
		refhash_rele(ev_hash, ke);
		mutex_exit(&ev_lock);
		return;
	}

	/* some other event */
	if (port_associate(evport, PORT_SOURCE_FD, (uintptr_t)ke->ke_fd,
	    POLLPRI, ke) < 0) {
		(void) bunyan_warn(tlog, "port_associate failed",
		    BUNYAN_T_INT32, "errno", errno,
		    BUNYAN_T_STRING, "errmsg", strerror(errno),
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_UINT32, "line", __LINE__,
		    BUNYAN_T_END);

		refhash_remove(ev_hash, ke);
		refhash_rele(ev_hash, ke);
		mutex_exit(&ev_lock);
		return;
	}
}

static void *
kbmd_event_loop(void *arg __unused)
{
	while (!kbmd_quit) {
		port_event_t pe = { 0 };

		if (port_get(evport, &pe, NULL) < 0) {
			if (errno == EINTR)
				continue;
			panic("port_get failed: %s", strerror(errno));
		}

		switch (pe.portev_source) {
		case PORT_SOURCE_FD:
			fd_event(pe.portev_user, pe.portev_events);
			break;
		}
	}

	return (NULL);
}

void
kbmd_event_init(int dfd)
{
	int rc;

	ev_hash = refhash_create(BUCKET_COUNT, event_hash, event_cmp,
	    event_free, sizeof (kbm_event_t), offsetof(kbm_event_t, ke_link),
	    offsetof(kbm_event_t, ke_pid), 0);

	if (ev_hash == NULL) {
		kbmd_dfatal(dfd, "cannot create event hash");
	}

	evport = port_create();
	if (evport == -1) {
		kbmd_dfatal(dfd, "unable to create event port");
	}

	rc = thr_create(NULL, 0, kbmd_event_loop, NULL, 0, &event_tid);
	if (rc != 0) {
		kbmd_dfatal(dfd, "unable to create event thread");
	}
}

void
kbmd_event_fini(void)
{
	int rc = thr_join(event_tid, NULL, NULL);

	if (rc != 0)
		errx(EXIT_FAILURE, "thr_join failed: %s", strerror(rc));
}
