//
//  devices.hpp
//  itlwm
//
//  Created by qcwap on 2020/3/14.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef __IF_IWN_NOTIF_WAIT_H__
#define __IF_IWN_NOTIF_WAIT_H__

#include <sys/queue.h>

#include <sys/_mutex.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOLib.h>

#define IWM_MAX_NOTIF_CMDS	5

struct iwm_rx_packet;
struct iwm_softc;

/**
 * struct iwm_notification_wait - notification wait entry
 * @entry: link for global list
 * @fn: Function called with the notification. If the function
 *      returns true, the wait is over, if it returns false then
 *      the waiter stays blocked. If no function is given, any
 *      of the listed commands will unblock the waiter.
 * @cmds: command IDs
 * @n_cmds: number of command IDs
 * @triggered: waiter should be woken up
 * @aborted: wait was aborted
 *
 * This structure is not used directly, to wait for a
 * notification declare it on the stack, and call
 * iwm_init_notification_wait() with appropriate
 * parameters. Then do whatever will cause the ucode
 * to notify the driver, and to wait for that then
 * call iwm_wait_notification().
 *
 * Each notification is one-shot. If at some point we
 * need to support multi-shot notifications (which
 * can't be allocated on the stack) we need to modify
 * the code for them.
 */
struct iwm_notification_wait {
	STAILQ_ENTRY(iwm_notification_wait) entry;

	int (*fn)(struct iwm_softc *sc, struct iwm_rx_packet *pkt, void *data);
	void *fn_data;

	uint16_t cmds[IWM_MAX_NOTIF_CMDS];
	uint8_t n_cmds;
	int triggered, aborted;
};

/* caller functions */
extern	struct iwm_notif_wait_data *iwm_notification_wait_init(
		struct iwm_softc *sc);
extern	void iwm_notification_wait_free(struct iwm_notif_wait_data *notif_data);
extern	void iwm_notification_wait_notify(
		struct iwm_notif_wait_data *notif_data, uint16_t cmd,
		struct iwm_rx_packet *pkt);
extern	void iwm_abort_notification_waits(
		struct iwm_notif_wait_data *notif_data);

/* user functions */
extern	void iwm_init_notification_wait(struct iwm_notif_wait_data *notif_data,
		struct iwm_notification_wait *wait_entry,
		const uint16_t *cmds, int n_cmds,
		int (*fn)(struct iwm_softc *sc,
			  struct iwm_rx_packet *pkt, void *data),
		void *fn_data);
extern	int iwm_wait_notification(struct iwm_notif_wait_data *notif_data,
		struct iwm_notification_wait *wait_entry, int timeout);
extern	void iwm_remove_notification(struct iwm_notif_wait_data *notif_data,
		struct iwm_notification_wait *wait_entry);

#endif  /* __IF_IWN_NOTIF_WAIT_H__ */
