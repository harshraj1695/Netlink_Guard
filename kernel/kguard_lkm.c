#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <net/netlink.h>

#define KGUARD_NETLINK_FAMILY 31
#define KGUARD_MAX_PAYLOAD 256
#define KGUARD_MAX_BLOCKED 128

enum kguard_msg_type {
    KGUARD_MSG_HELLO = 1,
    KGUARD_MSG_STATUS_REQ = 2,
    KGUARD_MSG_STATUS_RESP = 3,
    KGUARD_MSG_BLOCK_IP = 4,
    KGUARD_MSG_UNBLOCK_IP = 5,
    KGUARD_MSG_EVENT = 6,
    KGUARD_MSG_LIST_REQ = 7,
    KGUARD_MSG_LIST_RESP = 8
};

struct kguard_msg {
    u16 type;
    u16 reserved;
    u32 pid;
    char payload[KGUARD_MAX_PAYLOAD];
};

static struct sock *nl_sock;
static DEFINE_SPINLOCK(blocklist_lock);
static __be32 blocked_ips[KGUARD_MAX_BLOCKED];
static size_t blocked_count;
static struct nf_hook_ops nf_ops[2];
static struct kprobe kp;
static struct proc_dir_entry *proc_entry;
static struct kobject *kguard_kobj;
static atomic64_t packets_seen = ATOMIC64_INIT(0);
static atomic64_t packets_dropped = ATOMIC64_INIT(0);
static atomic64_t connect_events = ATOMIC64_INIT(0);
static bool guard_enabled = true;

static bool kguard_is_blocked(__be32 ip)
{
    size_t i;
    bool blocked = false;

    spin_lock(&blocklist_lock);
    for (i = 0; i < blocked_count; i++) {
        if (blocked_ips[i] == ip) {
            blocked = true;
            break;
        }
    }
    spin_unlock(&blocklist_lock);

    return blocked;
}

static int kguard_block_ip(__be32 ip)
{
    size_t i;
    int rc = 0;

    spin_lock(&blocklist_lock);
    for (i = 0; i < blocked_count; i++) {
        if (blocked_ips[i] == ip) {
            goto out;
        }
    }
    if (blocked_count >= KGUARD_MAX_BLOCKED) {
        rc = -ENOMEM;
        goto out;
    }
    blocked_ips[blocked_count++] = ip;
out:
    spin_unlock(&blocklist_lock);
    return rc;
}

static int kguard_unblock_ip(__be32 ip)
{
    size_t i;
    int rc = -ENOENT;

    spin_lock(&blocklist_lock);
    for (i = 0; i < blocked_count; i++) {
        if (blocked_ips[i] == ip) {
            size_t j;
            for (j = i; j + 1 < blocked_count; j++)
                blocked_ips[j] = blocked_ips[j + 1];
            blocked_count--;
            rc = 0;
            break;
        }
    }
    spin_unlock(&blocklist_lock);
    return rc;
}

static int kguard_send_reply(const struct nlmsghdr *req, u16 type, const char *payload)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct kguard_msg *msg;
    size_t size = sizeof(*msg);
    int rc;

    if (!req || !nl_sock)
        return -ENOTCONN;

    skb = nlmsg_new(size, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;

    nlh = nlmsg_put(skb, 0, req->nlmsg_seq, NLMSG_DONE, size, 0);
    if (!nlh) {
        kfree_skb(skb);
        return -EMSGSIZE;
    }

    msg = nlmsg_data(nlh);
    memset(msg, 0, sizeof(*msg));
    msg->type = type;
    msg->pid = 0;
    if (payload)
        strscpy(msg->payload, payload, sizeof(msg->payload));

    rc = nlmsg_unicast(nl_sock, skb, req->nlmsg_pid);
    if (rc < 0)
        pr_warn("kguard: netlink send failed: %d\n", rc);
    return rc;
}

static void kguard_send_list(const struct nlmsghdr *req)
{
    char out[KGUARD_MAX_PAYLOAD];
    size_t i;
    size_t used = 0;
    int n;

    out[0] = '\0';

    spin_lock(&blocklist_lock);
    for (i = 0; i < blocked_count; i++) {
        n = scnprintf(out + used, sizeof(out) - used,
                      "%s%pI4", used ? "," : "", &blocked_ips[i]);
        if (n <= 0 || n >= (int)(sizeof(out) - used))
            break;
        used += (size_t)n;
    }
    spin_unlock(&blocklist_lock);

    if (!used)
        strscpy(out, "none", sizeof(out));
    kguard_send_reply(req, KGUARD_MSG_LIST_RESP, out);
}

static void kguard_send_status(const struct nlmsghdr *req)
{
    char out[KGUARD_MAX_PAYLOAD];
    size_t cnt;

    spin_lock(&blocklist_lock);
    cnt = blocked_count;
    spin_unlock(&blocklist_lock);

    scnprintf(out, sizeof(out),
              "enabled=%d blocked=%zu packets_seen=%lld packets_dropped=%lld connect_events=%lld",
              guard_enabled ? 1 : 0, cnt,
              (long long)atomic64_read(&packets_seen),
              (long long)atomic64_read(&packets_dropped),
              (long long)atomic64_read(&connect_events));
    kguard_send_reply(req, KGUARD_MSG_STATUS_RESP, out);
}

static unsigned int kguard_nf_hook(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    (void)priv;
    (void)state;

    if (!skb)
        return NF_ACCEPT;

    atomic64_inc(&packets_seen);

    if (!guard_enabled)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    if (kguard_is_blocked(iph->daddr)) {
        atomic64_inc(&packets_dropped);
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static int kguard_pre_sys_connect(struct kprobe *p, struct pt_regs *regs)
{
    (void)p;
    (void)regs;
    atomic64_inc(&connect_events);
    return 0;
}

static int kguard_parse_ipv4(const char *text, __be32 *ip)
{
    u8 bytes[4];
    if (sscanf(text, "%hhu.%hhu.%hhu.%hhu",
               &bytes[0], &bytes[1], &bytes[2], &bytes[3]) != 4)
        return -EINVAL;
    *ip = htonl((bytes[0] << 24) | (bytes[1] << 16) |
                (bytes[2] << 8) | bytes[3]);
    return 0;
}

static void kguard_netlink_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct kguard_msg *msg;
    __be32 ip;

    if (!skb)
        return;

    nlh = nlmsg_hdr(skb);
    if (nlh->nlmsg_len < nlmsg_msg_size(sizeof(*msg)))
        return;

    msg = nlmsg_data(nlh);

    switch (msg->type) {
    case KGUARD_MSG_HELLO:
        kguard_send_reply(nlh, KGUARD_MSG_EVENT, "{\"event\":\"hello_ack\"}");
        break;
    case KGUARD_MSG_STATUS_REQ:
        kguard_send_status(nlh);
        break;
    case KGUARD_MSG_BLOCK_IP:
        if (!kguard_parse_ipv4(msg->payload, &ip)) {
            int rc = kguard_block_ip(ip);
            kguard_send_reply(nlh, KGUARD_MSG_EVENT,
                               rc == 0 ? "{\"event\":\"ip_blocked\"}"
                                       : "{\"event\":\"ip_block_failed\"}");
        }
        break;
    case KGUARD_MSG_UNBLOCK_IP:
        if (!kguard_parse_ipv4(msg->payload, &ip)) {
            int rc = kguard_unblock_ip(ip);
            kguard_send_reply(nlh, KGUARD_MSG_EVENT,
                               rc == 0 ? "{\"event\":\"ip_unblocked\"}"
                                       : "{\"event\":\"ip_unblock_failed\"}");
        }
        break;
    case KGUARD_MSG_LIST_REQ:
        kguard_send_list(nlh);
        break;
    default:
        break;
    }
}

static int kguard_proc_show(struct seq_file *m, void *v)
{
    size_t i;
    (void)v;

    seq_printf(m, "enabled: %d\n", guard_enabled ? 1 : 0);
    seq_printf(m, "packets_seen: %lld\n", (long long)atomic64_read(&packets_seen));
    seq_printf(m, "packets_dropped: %lld\n", (long long)atomic64_read(&packets_dropped));
    seq_printf(m, "connect_events: %lld\n", (long long)atomic64_read(&connect_events));

    spin_lock(&blocklist_lock);
    seq_printf(m, "blocked_count: %zu\n", blocked_count);
    seq_puts(m, "blocked_ips: ");
    for (i = 0; i < blocked_count; i++)
        seq_printf(m, "%s%pI4", i ? "," : "", &blocked_ips[i]);
    if (!blocked_count)
        seq_puts(m, "none");
    seq_putc(m, '\n');
    spin_unlock(&blocklist_lock);
    return 0;
}

static int kguard_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, kguard_proc_show, NULL);
}

static const struct proc_ops kguard_proc_ops = {
    .proc_open = kguard_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static ssize_t enabled_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    (void)kobj;
    (void)attr;
    return scnprintf(buf, PAGE_SIZE, "%d\n", guard_enabled ? 1 : 0);
}

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
                             const char *buf, size_t count)
{
    bool val;
    (void)kobj;
    (void)attr;
    if (kstrtobool(buf, &val))
        return -EINVAL;
    guard_enabled = val;
    return count;
}

static struct kobj_attribute enabled_attr = __ATTR(enabled, 0644, enabled_show, enabled_store);

static int __init kguard_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = kguard_netlink_recv,
    };
    int rc;

    nl_sock = netlink_kernel_create(&init_net, KGUARD_NETLINK_FAMILY, &cfg);
    if (!nl_sock)
        return -ENOMEM;

    nf_ops[0].hook = kguard_nf_hook;
    nf_ops[0].pf = NFPROTO_IPV4;
    nf_ops[0].hooknum = NF_INET_PRE_ROUTING;
    nf_ops[0].priority = NF_IP_PRI_FIRST;

    nf_ops[1].hook = kguard_nf_hook;
    nf_ops[1].pf = NFPROTO_IPV4;
    nf_ops[1].hooknum = NF_INET_LOCAL_OUT;
    nf_ops[1].priority = NF_IP_PRI_FIRST;

    rc = nf_register_net_hooks(&init_net, nf_ops, ARRAY_SIZE(nf_ops));
    if (rc)
        goto out_nl;

    kp.symbol_name = "__x64_sys_connect";
    kp.pre_handler = kguard_pre_sys_connect;
    rc = register_kprobe(&kp);
    if (rc) {
        pr_warn("kguard: kprobe registration failed: %d\n", rc);
        kp.symbol_name = "sys_connect";
        rc = register_kprobe(&kp);
        if (rc)
            goto out_nf;
    }

    proc_entry = proc_create("kguard", 0444, NULL, &kguard_proc_ops);
    if (!proc_entry) {
        rc = -ENOMEM;
        goto out_probe;
    }

    kguard_kobj = kobject_create_and_add("kguard", kernel_kobj);
    if (!kguard_kobj) {
        rc = -ENOMEM;
        goto out_proc;
    }

    rc = sysfs_create_file(kguard_kobj, &enabled_attr.attr);
    if (rc)
        goto out_kobj;

    pr_info("kguard: module loaded\n");
    return 0;

out_kobj:
    kobject_put(kguard_kobj);
out_proc:
    proc_remove(proc_entry);
out_probe:
    unregister_kprobe(&kp);
out_nf:
    nf_unregister_net_hooks(&init_net, nf_ops, ARRAY_SIZE(nf_ops));
out_nl:
    netlink_kernel_release(nl_sock);
    return rc;
}

static void __exit kguard_exit(void)
{
    if (kguard_kobj) {
        sysfs_remove_file(kguard_kobj, &enabled_attr.attr);
        kobject_put(kguard_kobj);
    }
    if (proc_entry)
        proc_remove(proc_entry);
    unregister_kprobe(&kp);
    nf_unregister_net_hooks(&init_net, nf_ops, ARRAY_SIZE(nf_ops));
    if (nl_sock)
        netlink_kernel_release(nl_sock);
    pr_info("kguard: module unloaded\n");
}

module_init(kguard_init);
module_exit(kguard_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kguard starter");
MODULE_DESCRIPTION("Kernel guard starter with netfilter, kprobe, netlink");
