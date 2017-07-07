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
 * Netlink communication strongly based on audit.c.
 */

#include <linux/rlimit_noti.h>

#include <net/sock.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <net/netns/generic.h>

#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/anon_inodes.h>
#include <linux/sched/signal.h>


struct rlimit_event_list {
	struct rlimit_event ev;
	union {
		struct rlimit_event_new_pid npid;
		struct rlimit_event_pid_dead dpid;
		struct rlimit_event_res_changed rchanged;
	} event_data;
	struct list_head node;
};

#define MAX_RLIMIT_EVENT_SIZE ({					\
			struct rlimit_event_list *_rl = NULL;	\
			sizeof(_rl->event_data);		\
})

struct rlimit_noti_ctx {
	struct mutex mutex;
	struct list_head rlimit_watchers;

	struct mutex events_mutex;
	wait_queue_head_t events_queue;
	struct list_head events;
};

struct rlimit_watcher {
	struct rlimit_noti_ctx *ctx;
	struct task_struct *task;

	struct list_head tsk_node;
	struct list_head ctx_node;

	uint64_t value;
	unsigned noti_all_changes:1;
};

/******************************************************************************
 * Public API
 ******************************************************************************/

void rlimit_noti_task_exit(struct task_struct *tsk)
{
	struct rlimit_watcher *w, *w2;
	int i;

	/* TODO: generate pid dead event when suitable */
	for (i = 0; i < ARRAY_SIZE(tsk->signal->rlimit_watchers); ++i) {
		list_for_each_entry_safe(w, w2,
					 &(tsk->signal->rlimit_watchers[i]),
					 tsk_node) {
			if (w->task != tsk)
				continue;
			list_del(&w->tsk_node);
			mutex_lock(&w->ctx->mutex);
			list_del(&w->ctx_node);
			mutex_unlock(&w->ctx->mutex);
			kfree(w);
		}
	}
}

static int rlimit_generate_res_changed_event(struct rlimit_noti_ctx *ctx,
					     struct task_struct *tsk,
					     unsigned resource,
					     uint64_t new, int mflags)
{
	struct rlimit_event_list *ev_list;

	ev_list = kzalloc(sizeof(*ev_list), mflags);
	if (!ev_list)
		return -ENOMEM;

	ev_list->ev.ev_type = RLIMIT_EVENT_TYPE_RES_CHANGED;
	ev_list->ev.size = sizeof(struct rlimit_event) + sizeof(struct rlimit_event_res_changed);

	/* TODO add here support for PID namespace */
	ev_list->event_data.rchanged.subj.pid = tsk->pid;
	ev_list->event_data.rchanged.subj.resource = resource;
	printk("New value %d\n", (int)new);
	ev_list->event_data.rchanged.new_value = new;

	INIT_LIST_HEAD(&ev_list->node);

	mutex_lock(&ctx->events_mutex);
	list_add_tail(&ev_list->node, &ctx->events);
	wake_up_interruptible(&ctx->events_queue);
	mutex_unlock(&ctx->events_mutex);

	return 0;
}

void rlimit_noti_res_changed(struct task_struct *tsk, unsigned res,
			     uint64_t old, uint64_t new, int mflags)
{
	struct rlimit_watcher *w;

	task_lock(tsk->group_leader);
	/* TODO this should be replaced with sth faster */
	list_for_each_entry(w, &tsk->signal->rlimit_watchers[res], tsk_node) {
		if (w->noti_all_changes ||
		    (w->value > old && w->value <= new) ||
		    (w->value > new && w->value <= old)) {
			/* ignore error as there is nothing we can do */
			rlimit_generate_res_changed_event(w->ctx, tsk,
							  res, new, mflags);
		}
	}
	task_unlock(tsk->group_leader);
}

/******************************************************************************
 * FD part
 ******************************************************************************/

static struct rlimit_watcher *alloc_rlimit_watcher(struct rlimit_noti_ctx *ctx,
						 struct task_struct *tsk,
						 uint64_t value, bool noti_all)
{
	struct rlimit_watcher *w;

	w = kzalloc(sizeof(*w), GFP_KERNEL);
	if (!w)
		return ERR_PTR(ENOMEM);

	INIT_LIST_HEAD(&w->tsk_node);
	INIT_LIST_HEAD(&w->ctx_node);

	w->ctx = ctx;
	w->task = tsk;
	w->value = value;
	w->noti_all_changes = noti_all;

	return w;
}

static void free_rlimit_watcher(struct rlimit_watcher *w)
{
	kfree(w);
}

static int add_new_watcher(struct rlimit_noti_ctx *ctx, struct task_struct *tsk,
			   int resource, uint64_t value, bool noti_all)
{
	struct rlimit_watcher *w;
	int ret = 0;

	if (resource >= RLIM_NLIMITS)
		return -EINVAL;

	w = alloc_rlimit_watcher(ctx, tsk, value, noti_all);
	if (IS_ERR(w))
		return PTR_ERR(w);

	read_lock(&tasklist_lock);
	if (!tsk->sighand) {
		ret = -ESRCH;
		goto out;
	}

	task_lock(tsk->group_leader);
	list_add_tail(&w->tsk_node, &tsk->signal->rlimit_watchers[resource]);
	task_unlock(tsk->group_leader);

	mutex_lock(&ctx->mutex);
	list_add_tail(&w->ctx_node, &ctx->rlimit_watchers);
	mutex_unlock(&ctx->mutex);

	ret = 0;
out:
	read_unlock(&tasklist_lock);
	return ret;
}

ssize_t rlimit_noti_read_event(struct file *file, char __user *buf,
			       size_t size, loff_t *ptr)
{
	struct rlimit_noti_ctx *ctx = file->private_data;
	struct rlimit_event_list *ev_list;
	size_t ret;

	/* TODO allow to read only part of event */
	if (size < MAX_RLIMIT_EVENT_SIZE)
		return -EINVAL;

	mutex_lock(&ctx->events_mutex);
#define READ_COND (!list_empty(&ctx->events))
	while (!READ_COND) {
		mutex_unlock(&ctx->events_mutex);

		if (wait_event_interruptible(ctx->events_queue, READ_COND))
			return -ERESTARTSYS;

		mutex_lock(&ctx->events_mutex);
	}

	ev_list = list_first_entry(&ctx->events, struct rlimit_event_list, node);
	list_del(&ev_list->node);
	mutex_unlock(&ctx->events_mutex);

	/* TODO handle fault */
	ret = copy_to_user(buf, &ev_list->ev, ev_list->ev.size);
	kfree(ev_list);

	return ret;
}

/* TODO implement poll
unsigned int rlimit_noti_poll(struct file *file, struct poll_table_struct *)
{

}
*/

static long rlimit_noti_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct rlimit_noti_ctx *ctx = file->private_data;
	int ret;

	switch (cmd) {
	case RLIMIT_SET_NOTI_ALL: {
		struct task_struct *tsk;
		struct rlimit_noti_subject subj;

		if (copy_from_user(&subj, (void __user *)arg, sizeof(subj)))
			return -EFAULT;

		rcu_read_lock();
		tsk = find_task_by_pid_ns(subj.pid, task_active_pid_ns(current));
		rcu_read_unlock();
		if (!tsk) {
			printk("No PID in current NS\n");
			return -EINVAL;
		}

		/* TODO check for duplicates before adding */
		ret = add_new_watcher(ctx, tsk, subj.resource, 0, true);
		break;
	}

	case RLIMIT_ADD_NOTI_LVL: {
		struct task_struct *tsk;
		struct rlimit_noti_level nlvl;

		if (copy_from_user(&nlvl, (void __user *)arg, sizeof(nlvl)))
			return -EFAULT;

		rcu_read_lock();
		tsk = find_task_by_pid_ns(nlvl.subj.pid,
					   task_active_pid_ns(current));
		rcu_read_unlock();
		if (!tsk) {
			printk("No PID in current NS\n");
			return -EINVAL;
		}

		/* TODO check for duplicates before adding */
		ret = add_new_watcher(ctx, tsk, nlvl.subj.resource,
				      nlvl.value, false);
		break;
	}

	case RLIMIT_CLEAR_NOTI_ALL:
	case RLIMIT_RM_NOTI_LVL:

	case RLIMIT_GET_NOTI_LVLS:
	case RLIMIT_GET_NOTI_LVL_COUNT:
		/* TODO: Implement me */
		ret = -ENOTSUPP;
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int rlimit_noti_release(struct inode *inode, struct file *file)
{
	struct rlimit_noti_ctx *ctx = file->private_data;
	struct rlimit_watcher *w;
	struct rlimit_event_list *ev_list;

	read_lock(&tasklist_lock);
	mutex_lock(&ctx->mutex);

	list_for_each_entry(w, &ctx->rlimit_watchers, ctx_node) {
		task_lock(w->task->group_leader);
		list_del(&w->tsk_node);
		task_unlock(w->task->group_leader);
	}
	read_unlock(&tasklist_lock);

	while (!list_empty(&ctx->rlimit_watchers)) {
		w = list_first_entry(&ctx->rlimit_watchers,
				     struct rlimit_watcher, ctx_node);
		list_del(&w->ctx_node);
		free_rlimit_watcher(w);
	}

	mutex_unlock(&ctx->mutex);

	mutex_lock(&ctx->events_mutex);
	while (!list_empty(&ctx->events)) {
		ev_list = list_first_entry(&ctx->events,
					   struct rlimit_event_list, node);
		list_del(&ev_list->node);
		kfree(ev_list);
	}
	mutex_unlock(&ctx->events_mutex);


	kfree(ctx);

	return 0;
}

static const struct file_operations rlimit_noti_fops = {
	.read = rlimit_noti_read_event,
	.release = rlimit_noti_release,
/* TODO .poll = rlimit_noti_poll, */
	.unlocked_ioctl = rlimit_noti_ioctl,
};

static int rlimit_noti_create_fd(void)
{
	struct rlimit_noti_ctx *ctx;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	mutex_init(&ctx->mutex);
	INIT_LIST_HEAD(&ctx->rlimit_watchers);
	mutex_init(&ctx->events_mutex);
	INIT_LIST_HEAD(&ctx->events);
	init_waitqueue_head(&ctx->events_queue);

	ret = anon_inode_getfd("rlimit_noti", &rlimit_noti_fops, ctx, 0);
	if (ret < 0)
		goto free_ctx;

	return ret;
free_ctx:
	kfree(ctx);
	return ret;
}



/******************************************************************************
 * netlink part
 ******************************************************************************/


/* private rlimit_noti network namespace index */
static unsigned int rlimit_noti_net_id;

/**
 * struct rlimit_noti_net - rlimit notification private network namespace data
 * @sk: communication socket
 */
struct rlimit_noti_net {
	struct sock *sk;
};

struct rlimit_noti_reply {
	__u32 portid;
	struct net *net;
	struct sk_buff *skb;
};

static struct sock *rlimit_noti_get_socket(const struct net *net)
{
	struct rlimit_noti_net *rn_net;

	if (!net)
		return NULL;

	rn_net = net_generic(net, rlimit_noti_net_id);
	return rn_net->sk;
}

static struct sk_buff *rlimit_noti_make_reply(int seq, int type,
					      void *payload, int size)
{
	struct sk_buff	*skb;
	struct nlmsghdr	*nl_header;
	int flags = 0;

	skb = nlmsg_new(size, GFP_KERNEL);
	if (!skb)
		return NULL;

	nl_header = nlmsg_put(skb, 0, seq, type, size, flags);
	if (!nl_header)
		goto free_skb;

	memcpy(nlmsg_data(nl_header), payload, size);

	return skb;

free_skb:
	kfree_skb(skb);
	return NULL;
}

static int rlimit_noti_send_reply_thread(void *arg)
{
	struct rlimit_noti_reply *reply = arg;
	struct sock *sk = rlimit_noti_get_socket(reply->net);

	/*
	 * Ignore failure. It'll only happen if the sender goes away,
	 * because our timeout is set to infinite.
	 */
	netlink_unicast(sk, reply->skb, reply->portid, 0);
	put_net(reply->net);
	kfree(reply);
	return 0;
}

static void rlimit_noti_send_reply(struct sk_buff *request_skb, int seq,
				   int type, void *payload, int size)
{
	struct net *net = sock_net(NETLINK_CB(request_skb).sk);
	struct sk_buff *skb;
	struct task_struct *tsk;
	struct rlimit_noti_reply *reply;

	reply = kmalloc(sizeof(*reply), GFP_KERNEL);
	if (!reply)
		return;

	skb = rlimit_noti_make_reply(seq, type, payload, size);
	if (!skb)
		goto out;

	reply->net = get_net(net);
	reply->portid = NETLINK_CB(request_skb).portid;
	reply->skb = skb;

	tsk = kthread_run(rlimit_noti_send_reply_thread, reply,
			  "rlimit_noti_send_reply");
	if (!IS_ERR(tsk))
		return;
	kfree_skb(skb);
out:
	kfree(reply);
}

static int rlimit_noti_netlink_ok(struct sk_buff *skb, u16 msg_type)
{
	/* TODO: put here some security and namespace checks */
	return 0;
}

static int rlimit_noti_receive_msg(struct sk_buff *skb,
				   struct nlmsghdr *nl_header)
{
	u32 seq_nb = nl_header->nlmsg_seq;
	u16 msg_type = nl_header->nlmsg_type;
	int ret;

	ret = rlimit_noti_netlink_ok(skb, msg_type);
	if (ret)
		return ret;

	switch (msg_type) {
	case RLIMIT_GET_NOTI_FD: {
		int fd = 10;

		fd = rlimit_noti_create_fd();
		if (fd < 0) {
			ret = fd;
			goto out;
		}
		rlimit_noti_send_reply(skb, seq_nb, RLIMIT_GET_NOTI_FD,
				       &fd, sizeof(fd));
		ret = 0;
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}
out:
	return ret;
}

static void rlimit_noti_netlink_receive(struct sk_buff *skb)
{
	struct nlmsghdr *nl_header;
	int len, ret;

	nl_header = nlmsg_hdr(skb);
	len = skb->len;

	while (nlmsg_ok(nl_header, len)) {
		ret = rlimit_noti_receive_msg(skb, nl_header);
		/* if err or if this message says it wants a response */
		if (ret || (nl_header->nlmsg_flags & NLM_F_ACK))
			netlink_ack(skb, nl_header, ret, NULL);

		nl_header = nlmsg_next(nl_header, &len);
	}
}

static int rlimit_noti_netlink_bind(struct net *net, int group)
{
	/* For now we allow everyone but maybe this should be limited? */
	return 0;
}

static int __net_init rlimit_noti_net_init(struct net *net)
{
	struct netlink_kernel_cfg cfg = {
		.input	= rlimit_noti_netlink_receive,
		.bind	= rlimit_noti_netlink_bind,
		.flags	= NL_CFG_F_NONROOT_RECV,
		.groups	= 1, /* Just one, the default */
	};
	struct rlimit_noti_net *rn_net = net_generic(net, rlimit_noti_net_id);

	rn_net->sk = netlink_kernel_create(net, NETLINK_RLIMIT_EVENTS, &cfg);
	if (rn_net->sk == NULL) {
		printk("cannot initialize netlink socket in namespace");
		return -ENOMEM;
	}
	rn_net->sk->sk_sndtimeo = MAX_SCHEDULE_TIMEOUT;

	return 0;

}

static void __net_exit rlimit_noti_net_exit(struct net *net)
{
	struct rlimit_noti_net *rn_net = net_generic(net, rlimit_noti_net_id);

	netlink_kernel_release(rn_net->sk);
}

static struct pernet_operations rlimit_noti_net_ops __net_initdata = {
	.init = rlimit_noti_net_init,
	.exit = rlimit_noti_net_exit,
	.id = &rlimit_noti_net_id,
	.size = sizeof(struct rlimit_noti_net),
};

static int __init rlimit_noti_init(void)
{
	return register_pernet_subsys(&rlimit_noti_net_ops);
}

static void __exit rlimit_noti_exit(void)
{
	unregister_pernet_subsys(&rlimit_noti_net_ops);
}

module_init(rlimit_noti_init);
module_exit(rlimit_noti_exit);
