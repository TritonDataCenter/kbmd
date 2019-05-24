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
#include <sys/list.h>
#include <sys/types.h>
#include "common.h"
#include "kbmd.h"
#include "pivy/errf.h"

typedef struct kbm_event {
	list_node_t ke_node;
	boolean_t ke_dead;
	int	ke_fd;
	pid_t	ke_pid;
	void	(*ke_cb)(pid_t, void *);
	void	*ke_arg;
} kbm_event_t;

static int evport = -1;
static mutex_t ev_lock = ERRORCHECKMUTEX;
static list_t ev_list;

thread_t event_tid;
extern volatile boolean_t kbmd_quit;

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
		free(evt);
		return (ret);
	}
	list_insert_tail(&ev_list, evt);
	mutex_exit(&ev_lock);

	return (ERRF_OK);
}

errf_t *
kbmd_unwatch_pid(pid_t pid)
{
	kbm_event_t *evt;

	mutex_enter(&ev_lock);
	for (evt = list_head(&ev_list); evt != NULL;
	    evt = list_next(&ev_list, evt)) {
		if (evt->ke_pid == pid) {
			if (port_dissociate(evport, PORT_SOURCE_FD,
			    (uintptr_t)evt->ke_pid) < 0 && errno == ENOENT)
				evt->ke_dead = B_TRUE;
			list_remove(&ev_list, evt);
			break;
		}
	}
	mutex_exit(&ev_lock);

	if (evt == NULL)
		return (errf("NotFoundError", NULL,
		    "tried to stop already unwatched pid %d", pid));

	if (!evt->ke_dead)
		free(evt);

	return (ERRF_OK);
}

static void
fd_event(kbm_event_t *ke, int pevents)
{
	mutex_enter(&ev_lock);
	if (ke->ke_dead) {
		free(ke);
		mutex_exit(&ev_lock);
		return;
	}

	if (!(pevents & POLLHUP)) {
		mutex_exit(&ev_lock);
		return;
	}

	ke->ke_cb(ke->ke_pid, ke->ke_arg);
	list_remove(&ev_list, ke);
	free(ke);
	mutex_exit(&ev_lock);
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

	list_create(&ev_list, sizeof (kbm_event_t),
	    offsetof(kbm_event_t, ke_node));

	evport = port_create();
	if (evport == -1)
		kbmd_dfatal(dfd, "unable to create event port");

	rc = thr_create(NULL, 0, kbmd_event_loop, NULL, 0, &event_tid);
	if (rc != 0)
		kbmd_dfatal(dfd, "unable to create event thread");
}

void
kbmd_event_fini(void)
{
	int rc = thr_join(event_tid, NULL, NULL);

	if (rc != 0)
		errx(EXIT_FAILURE, "thr_join failed: %s", strerror(rc));
}
