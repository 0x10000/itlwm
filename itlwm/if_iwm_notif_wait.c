//
//  devices.hpp
//  itlwm
//
//  Created by qcwap on 2020/3/14.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/queue.h>

#include "if_iwm_notif_wait.h"

#define	IWM_WAIT_LOCK_INIT(_n, _s) \
	mtx_init(&(_n)->lk_mtx, (_s), 0, 0);
#define	IWM_WAIT_LOCK(_n)		mtx_lock(&(_n)->lk_mtx)
#define	IWM_WAIT_UNLOCK(_n)		mtx_unlock(&(_n)->lk_mtx)
#define	IWM_WAIT_LOCK_DESTROY(_n)	mtx_destroy(&(_n)->lk_mtx)

struct iwm_notif_wait_data {
	struct mtx lk_mtx;
	char lk_buf[32];
	STAILQ_HEAD(, iwm_notification_wait) list;
	struct iwm_softc *sc;
};

struct iwm_notif_wait_data *
iwm_notification_wait_init(struct iwm_softc *sc)
{
	struct iwm_notif_wait_data *data;

	data = (struct iwm_notif_wait_data *)IOMalloc(sizeof(*data));
	if (data != NULL) {
        memset(data, 0, sizeof(*data));
		snprintf(data->lk_buf, 32, "iwm wait_notif");
		IWM_WAIT_LOCK_INIT(data, data->lk_buf);
		STAILQ_INIT(&data->list);
		data->sc = sc;
	}

	return data;
}

void
iwm_notification_wait_free(struct iwm_notif_wait_data *notif_data)
{
	IWM_WAIT_LOCK_DESTROY(notif_data);
	IOFree(notif_data, sizeof(*notif_data));
}

/* XXX Get rid of separate cmd argument, like in iwlwifi's code */
void
iwm_notification_wait_notify(struct iwm_notif_wait_data *notif_data,
    uint16_t cmd, struct iwm_rx_packet *pkt)
{
	struct iwm_notification_wait *wait_entry;

	IWM_WAIT_LOCK(notif_data);
	STAILQ_FOREACH(wait_entry, &notif_data->list, entry) {
		int found = FALSE;
		int i;

		/*
		 * If it already finished (triggered) or has been
		 * aborted then don't evaluate it again to avoid races,
		 * Otherwise the function could be called again even
		 * though it returned true before
		 */
		if (wait_entry->triggered || wait_entry->aborted)
			continue;

		for (i = 0; i < wait_entry->n_cmds; i++) {
			if (cmd == wait_entry->cmds[i]) {
				found = TRUE;
				break;
			}
		}
		if (!found)
			continue;

		if (!wait_entry->fn ||
		    wait_entry->fn(notif_data->sc, pkt, wait_entry->fn_data)) {
			wait_entry->triggered = 1;
			wakeup(wait_entry);
		}
	}
	IWM_WAIT_UNLOCK(notif_data);
}

void
iwm_abort_notification_waits(struct iwm_notif_wait_data *notif_data)
{
	struct iwm_notification_wait *wait_entry;

	IWM_WAIT_LOCK(notif_data);
	STAILQ_FOREACH(wait_entry, &notif_data->list, entry) {
		wait_entry->aborted = 1;
		wakeup(wait_entry);
	}
	IWM_WAIT_UNLOCK(notif_data);
}

void
iwm_init_notification_wait(struct iwm_notif_wait_data *notif_data,
    struct iwm_notification_wait *wait_entry, const uint16_t *cmds, int n_cmds,
    int (*fn)(struct iwm_softc *sc, struct iwm_rx_packet *pkt, void *data),
    void *fn_data)
{
	KASSERT(n_cmds <= IWM_MAX_NOTIF_CMDS,
	    ("n_cmds %d is too large", n_cmds));
	wait_entry->fn = fn;
	wait_entry->fn_data = fn_data;
	wait_entry->n_cmds = n_cmds;
	memcpy(wait_entry->cmds, cmds, n_cmds * sizeof(uint16_t));
	wait_entry->triggered = 0;
	wait_entry->aborted = 0;

	IWM_WAIT_LOCK(notif_data);
	STAILQ_INSERT_TAIL(&notif_data->list, wait_entry, entry);
	IWM_WAIT_UNLOCK(notif_data);
}

int
iwm_wait_notification(struct iwm_notif_wait_data *notif_data,
    struct iwm_notification_wait *wait_entry, int timeout)
{
	int ret = 0;
    struct timespec ts;

	IWM_WAIT_LOCK(notif_data);
    ts.tv_nsec = timeout;
	if (!wait_entry->triggered && !wait_entry->aborted) {
		ret = msleep(wait_entry, notif_data->lk_mtx.mtx_lock, 0, (const char*)"iwm_notif",
		    &ts);
	}
	STAILQ_REMOVE(&notif_data->list, wait_entry, iwm_notification_wait,
	    entry);
	IWM_WAIT_UNLOCK(notif_data);

	return ret;
}

void
iwm_remove_notification(struct iwm_notif_wait_data *notif_data,
    struct iwm_notification_wait *wait_entry)
{
	IWM_WAIT_LOCK(notif_data);
	STAILQ_REMOVE(&notif_data->list, wait_entry, iwm_notification_wait,
	    entry);
	IWM_WAIT_UNLOCK(notif_data);
}
