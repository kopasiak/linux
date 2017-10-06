/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _LINUX_RLIMIT_NOTI_H_
#define _LINUX_RLIMIT_NOTI_H_

#include <uapi/linux/rlimit_noti.h>

struct rlimit_noti_ctx {
	/* for mdification protection */
	spinlock_t lock;
	/* protected by RCU */
	struct list_head watchers[RLIM_NLIMITS];

	unsigned process_dead:1;
};

#ifdef CONFIG_RLIMIT_NOTIFICATION

int rlimit_noti_task_fork(struct task_struct *parent, struct task_struct *child);

void rlimit_noti_task_exit(struct task_struct *tsk);

int rlimit_noti_watch_active(struct task_struct *tsk, unsigned res);

void rlimit_noti_res_changed(struct task_struct *tsk, unsigned res,
			     uint64_t old, uint64_t new);

#else
//int rlimit_noti_task_fork(struct task_struct *parent, struct task_struct *child);

//void rlimit_noti_task_exit(struct task_struct *tsk);

static inline int rlimit_noti_watch_active(struct task_struct *tsk,
					   unsigned res)
{
	return 0;
}

static inline void rlimit_noti_res_changed(struct task_struct *tsk,
					   unsigned res,
					   uint64_t old, uint64_t new)
{
}

#endif /* CONFIG_RLIMIT_NOTIFICATION */
#endif /* _LINUX_RLIMIT_NOTI_H_ */
