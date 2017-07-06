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

#ifndef _UAPI_LINUX_RLIMIT_NOTI_H_
#define _UAPI_LINUX_RLIMIT_NOTI_H_

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/resource.h>
#else
#include <stdint.h>
#endif

#define RLIMIT_GET_NOTI_FD 1000

/* ioctl's */
#define RLIMIT_ADD_NOTI_LVL 1
#define RLIMIT_RM_NOTI_LVL 2

#define RLIMIT_SET_NOTI_ALL 3
#define RLIMIT_UNSET_NOTI_ALL 4

/*
 * For future (notify every 5, 10 units change):
 * #define RLIMIT_SET_NOTI_STEP 5
 */

#define RLIMIT_GET_NOTI_LVL 6
#define RLIMIT_GET_NOTI_LVL_COUNT 7

/* Flags for ioctl's */
#define RLIMIT_FLAG_NO_INHERIT 1u << 0
#define RLIMIT_FLAG_RECURSIVE 1u << 1

struct rlimit_noti_level {
	pid_t pid;
	uint32_t resource;
	uint64_t value;
	uint32_t flags;
};

struct rlimit_event {
	uint32_t ev_type;
	size_t size;
};

struct rlimit_event_new_pid {
	pid_t parent;
	pid_t new_pid;
};

struct rlimit_event_pid_dead {
	pid_t pid;
};

struct rlimit_event_res_changed {
	pid_t pid;
	uint32_t resource;
	uint64_t new_value;
};

#endif /* _UAPI_LINUX_RLIMIT_NOTI_H_ */
