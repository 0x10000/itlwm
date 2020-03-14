//
//  _mutex.cpp
//  freewm
//
//  Created by qcwap on 2020/3/12.
//  Copyright © 2020 zxystd. All rights reserved.
//

#include "_mutex.h"

lck_grp_t *audit_lck_grp = lck_grp_alloc_init("Audit", LCK_GRP_ATTR_NULL);

/*
 * BSD Mutexes.
 */
void    _audit_mtx_init(struct mtx *mp, __unused const char *lckname)
{
    mp->mtx_lock = lck_mtx_alloc_init(audit_lck_grp, LCK_ATTR_NULL);
}

void    _audit_mtx_destroy(struct mtx *mp)
{
    if (mp->mtx_lock) {
        lck_mtx_free(mp->mtx_lock, audit_lck_grp);
        mp->mtx_lock = NULL;
    }
}
