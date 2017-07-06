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

		rlimit_noti_send_reply(skb, seq_nb, RLIMIT_GET_NOTI_FD,
				       &fd, sizeof(fd));
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

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
