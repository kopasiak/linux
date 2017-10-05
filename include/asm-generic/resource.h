#ifndef _ASM_GENERIC_RESOURCE_H
#define _ASM_GENERIC_RESOURCE_H

#include <uapi/asm-generic/resource.h>
#include <linux/spinlock.h>

/*
 * boot-time rlimit defaults for the init task:
 */
#define INIT_RLIMITS							\
{									\
	[RLIMIT_CPU]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_FSIZE]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_DATA]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_STACK]		= {       _STK_LIM,  RLIM_INFINITY },	\
	[RLIMIT_CORE]		= {              0,  RLIM_INFINITY },	\
	[RLIMIT_RSS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_NPROC]		= {              0,              0 },	\
	[RLIMIT_NOFILE]		= {   INR_OPEN_CUR,   INR_OPEN_MAX },	\
	[RLIMIT_MEMLOCK]	= {    MLOCK_LIMIT,    MLOCK_LIMIT },	\
	[RLIMIT_AS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_LOCKS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_SIGPENDING]	= { 		0,	       0 },	\
	[RLIMIT_MSGQUEUE]	= {   MQ_BYTES_MAX,   MQ_BYTES_MAX },	\
	[RLIMIT_NICE]		= { 0, 0 },				\
	[RLIMIT_RTPRIO]		= { 0, 0 },				\
	[RLIMIT_RTTIME]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
}

#ifdef CONFIG_RLIMIT_NOTIFICATION

#define INIT_RLIMIT_WATCHER(watchers, limit)	\
	[limit] = LIST_HEAD_INIT(watchers[limit])

#define INIT_RLIMIT_WATCHERS(watchers)				\
{								\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_CPU),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_FSIZE),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_DATA),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_STACK),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_CORE),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_RSS),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_NPROC),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_NOFILE),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_MEMLOCK),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_AS),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_LOCKS),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_SIGPENDING),	\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_MSGQUEUE),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_NICE),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_RTPRIO),		\
	INIT_RLIMIT_WATCHER(watchers, RLIMIT_RTTIME),		\
}

#define INIT_RLIMIT_EVENTS_CTX(sig)					\
sig.rlimit_events_ctx = {						\
	.lock = __SPIN_LOCK_UNLOCKED(sig.rlimit_events_ctx.lock)	\
	.watchers = INIT_RLIMIT_WATCHERS(sig.rlimit_events_ctx.watchers),\
	.process_dead = 0,						\
},
#else
#define INIT_RLIMIT_EVENTS_CTX(sig)
#endif /* CONFIG_RLIMIT_NOTIFICATION */

#endif
