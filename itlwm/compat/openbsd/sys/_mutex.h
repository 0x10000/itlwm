//
//  _mutex.h
//  freewm
//
//  Created by qcwap on 2020/3/10.
//  Copyright © 2020 zxystd. All rights reserved.
//

#ifndef _mutex_h
#define _mutex_h

#include <sys/lock.h>

#define AU_MAX_LCK_NAME 32

#define MA_OWNED 1
#define MA_NOTOWNED 2
#define    mtx_assert_(m, what, file, line)
/*
 * BSD mutex.
 */
struct mtx {
    lck_mtx_t       *mtx_lock;
#if DIAGNOSTIC
    char             mtx_name[AU_MAX_LCK_NAME];
#endif
};

/*
 * BSD rw lock.
 */
struct rwlock {
    lck_rw_t        *rw_lock;
#if DIAGNOSTIC
    char             rw_name[AU_MAX_LCK_NAME];
#endif
};

/*
 * Sleep lock.
 */
struct slck {
    lck_mtx_t       *sl_mtx;
    int              sl_locked;
    int              sl_waiting;
#if DIAGNOSTIC
    char             sl_name[AU_MAX_LCK_NAME];
#endif
};

/*
 * Recursive lock.
 */
struct rlck {
    lck_mtx_t       *rl_mtx;
    uint32_t         rl_recurse;
    thread_t         rl_thread;
#if DIAGNOSTIC
    char             rl_name[AU_MAX_LCK_NAME];
#endif
};

/*
 * BSD Mutexes.
 */
void    _audit_mtx_init(struct mtx *mp, __unused const char *lckname);

void    _audit_mtx_destroy(struct mtx *mp);

#define mtx_init(mp, name, type, opts) \
                            _audit_mtx_init(mp, name)
#define mtx_lock(mp)            lck_mtx_lock((mp)->mtx_lock)
#define mtx_unlock(mp)          lck_mtx_unlock((mp)->mtx_lock)
#define mtx_destroy(mp)         _audit_mtx_destroy(mp)
#define mtx_yield(mp)           lck_mtx_yield((mp)->mtx_lock)

#endif /* _mutex_h */
