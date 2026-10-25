// SPDX-License-Identifier: GPL-2.0
/*
 * u6e-pcc: mirror one client's offloaded TCP and UDP flows in NSS.
 *
 * ECM's per-connection classifier (PCC) asks its one registrant about each
 * connection it is about to accelerate, naming the MAC addresses of both
 * ends. While a target MAC is set, the target's TCP and UDP connections are
 * accelerated with an NSS mirror rule for both directions, so the NSS core
 * copies the first snaplen bytes of each of their packets to the mirror
 * netdev while they stay offloaded; the target's other connections are
 * denied acceleration and stay on the CPU, where AF_PACKET sees them.
 * Every other connection is permitted, as with no registrant; with no
 * target the callback costs one comparison.
 *
 * Use (the image loads it after ecm and qca-nss-mirror, once the mirror
 * instance exists; all files root only):
 *	echo create > /proc/sys/dev/nss/mirror/config	(makes mirror.0)
 *	modprobe u6e-pcc [mirror=mirror.0]
 *	echo 128 > /sys/kernel/debug/u6e-pcc/snaplen	(64-65535; default 128)
 *	echo 02:00:00:00:00:01 > /sys/kernel/debug/u6e-pcc/target
 *	echo none > /sys/kernel/debug/u6e-pcc/target
 * Setting the first target configures the mirror instance with the snaplen
 * (which can change only while there is no target) and enables it; each
 * target change then decelerates the previous target's connections and the
 * new one's, which ECM accelerates again without and with the mirror rule;
 * "none" decelerates the target's connections and disables the mirror.
 *
 * Registering makes ECM defunct every connection once, and its PCC then
 * keeps connections to port 53 on the CPU (ecm_classifier_pcc_process()).
 * ECM holds this module while it is registered, so it stays until reboot.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/hex.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <ecm_classifier_pcc_public.h>
#include <nss_mirror_public.h>

#define U6E_PCC_SNAPLEN_MIN 64

static char *mirror = "mirror.0";
module_param(mirror, charp, 0444);
MODULE_PARM_DESC(mirror, "NSS mirror netdev the target's flows are copied to");

/*
 * The target a callback reads under RCU. It is replaced, never changed,
 * and freed only after a grace period.
 */
struct u6e_pcc_target {
	u8 mac[ETH_ALEN] __aligned(2);
	struct net_device *mirror;
	struct rcu_head rcu;
};

static struct u6e_pcc_target __rcu *u6e_pcc_target;

/*
 * The mirror netdev, held while there is a target, and the snaplen it is
 * configured with. Changed under u6e_pcc_lock.
 */
static DEFINE_MUTEX(u6e_pcc_lock);
static struct net_device *u6e_pcc_mirror_dev;
static netdevice_tracker u6e_pcc_mirror_tracker;
static u16 u6e_pcc_snaplen = 128;

static struct dentry *u6e_pcc_dir;

/*
 * u6e_pcc_classify()
 *	The answer for one connection, from the MACs of its two ends.
 *
 * ECM calls this from its netfilter and bridge hooks, inside nf_hook()'s
 * RCU read side, and reads the mirror netdev it is given before that
 * section ends; u6e_pcc_set() waits a grace period before it releases one.
 */
static ecm_classifier_pcc_result_t u6e_pcc_classify(const u8 *src_mac, const u8 *dest_mac,
						    int protocol,
						    struct ecm_classifier_pcc_info *cinfo)
{
	ecm_classifier_pcc_result_t result = ECM_CLASSIFIER_PCC_RESULT_PERMITTED;
	const struct u6e_pcc_target *t;

	if (!rcu_access_pointer(u6e_pcc_target))
		return result;

	rcu_read_lock();
	t = rcu_dereference(u6e_pcc_target);
	if (t && (ether_addr_equal_unaligned(src_mac, t->mac) ||
		  ether_addr_equal_unaligned(dest_mac, t->mac))) {
		if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
			cinfo->feature_flags |= ECM_CLASSIFIER_PCC_FEATURE_MIRROR;
			cinfo->output_params.mirror.tuple_mirror_dev = t->mirror;
			cinfo->output_params.mirror.tuple_ret_mirror_dev = t->mirror;
		} else {
			result = ECM_CLASSIFIER_PCC_RESULT_DENIED;
		}
	}
	rcu_read_unlock();

	return result;
}

static ecm_classifier_pcc_result_t
u6e_pcc_get_accel_info_v4(struct ecm_classifier_pcc_registrant *r,
			  u8 *src_mac, __be32 src_ip, int src_port,
			  u8 *dest_mac, __be32 dest_ip, int dest_port,
			  int protocol, struct ecm_classifier_pcc_info *cinfo)
{
	return u6e_pcc_classify(src_mac, dest_mac, protocol, cinfo);
}

static ecm_classifier_pcc_result_t
u6e_pcc_get_accel_info_v6(struct ecm_classifier_pcc_registrant *r,
			  u8 *src_mac, struct in6_addr *src_ip, int src_port,
			  u8 *dest_mac, struct in6_addr *dest_ip, int dest_port,
			  int protocol, struct ecm_classifier_pcc_info *cinfo)
{
	return u6e_pcc_classify(src_mac, dest_mac, protocol, cinfo);
}

/*
 * The registrant's references, as ecm_classifier_pcc_public.h's contract
 * asks: ECM takes one while registered and one around each callback, and
 * makes no call once they are all dropped. The registrant is static and
 * the module stays, so the count guards nothing that could be freed.
 */
static void u6e_pcc_ref(struct ecm_classifier_pcc_registrant *r)
{
	atomic_inc(&r->ref_count);
}

static void u6e_pcc_deref(struct ecm_classifier_pcc_registrant *r)
{
	WARN_ON_ONCE(atomic_dec_return(&r->ref_count) < 0);
}

static struct ecm_classifier_pcc_registrant u6e_pcc_registrant = {
	.version = 1,
	.ref_count = ATOMIC_INIT(1),
	.this_module = THIS_MODULE,
	.ref = u6e_pcc_ref,
	.deref = u6e_pcc_deref,
	.get_accel_info_v4 = u6e_pcc_get_accel_info_v4,
	.get_accel_info_v6 = u6e_pcc_get_accel_info_v6,
};

/*
 * u6e_pcc_mirror_get()
 *	Hold the mirror netdev and configure and enable its NSS instance.
 */
static int u6e_pcc_mirror_get(void)
{
	struct net_device *dev;

	dev = netdev_get_by_name(&init_net, mirror, &u6e_pcc_mirror_tracker, GFP_KERNEL);
	if (!dev)
		return -ENODEV;

	if (nss_mirror_configure(dev, NSS_MIRROR_PKT_CLONE_POINT_DEFAULT, u6e_pcc_snaplen, 0) ||
	    nss_mirror_enable(dev)) {
		netdev_put(dev, &u6e_pcc_mirror_tracker);
		return -EIO;
	}

	u6e_pcc_mirror_dev = dev;
	return 0;
}

/*
 * u6e_pcc_mirror_put()
 *	Release the mirror netdev, disabling its NSS instance unless the
 *	netdev is being unregistered (which destroys the instance).
 */
static void u6e_pcc_mirror_put(bool disable)
{
	if (disable && nss_mirror_disable(u6e_pcc_mirror_dev))
		pr_warn("could not disable %s\n", u6e_pcc_mirror_dev->name);

	netdev_put(u6e_pcc_mirror_dev, &u6e_pcc_mirror_tracker);
	u6e_pcc_mirror_dev = NULL;
}

/*
 * u6e_pcc_set()
 *	Make mac (NULL: none) the target; with none, release the mirror,
 *	disabling it if asked. Called with u6e_pcc_lock held.
 *
 * The grace period after the switch ends every callback that may have
 * answered for the previous target, and ECM adds a connection to its
 * database before it classifies it, so the decelerations below reach
 * every connection that got the old answer; the next ones get the new.
 */
static int u6e_pcc_set(const u8 *mac, bool disable)
{
	struct u6e_pcc_target *new = NULL, *old;
	int ret;

	old = rcu_dereference_protected(u6e_pcc_target, lockdep_is_held(&u6e_pcc_lock));
	if (!old && !mac)
		return 0;

	if (mac) {
		new = kzalloc_obj(*new);
		if (!new)
			return -ENOMEM;

		if (!u6e_pcc_mirror_dev) {
			ret = u6e_pcc_mirror_get();
			if (ret) {
				kfree(new);
				return ret;
			}
		}
		ether_addr_copy(new->mac, mac);
		new->mirror = u6e_pcc_mirror_dev;
	}

	rcu_assign_pointer(u6e_pcc_target, new);
	synchronize_rcu();

	if (old) {
		ecm_classifier_pcc_decel_by_mac_addr(old->mac);
		pr_info("stopped mirroring %pM\n", old->mac);
		kfree(old);
	}
	if (new) {
		ecm_classifier_pcc_decel_by_mac_addr(new->mac);
		pr_info("mirroring %pM to %s, %u bytes a packet\n", new->mac,
			new->mirror->name, u6e_pcc_snaplen);
	} else {
		u6e_pcc_mirror_put(disable);
	}

	return 0;
}

/*
 * u6e_pcc_write_line()
 *	Copy one write of up to len - 1 bytes into buf, without its newline.
 */
static int u6e_pcc_write_line(char *buf, size_t len, const char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	if (*ppos || !count || count >= len)
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	buf[count] = '\0';
	if (buf[count - 1] == '\n')
		buf[count - 1] = '\0';

	return 0;
}

static ssize_t u6e_pcc_target_read(struct file *file, char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	const struct u6e_pcc_target *t;
	char buf[MAC_ADDR_STR_LEN + 2];
	int len;

	rcu_read_lock();
	t = rcu_dereference(u6e_pcc_target);
	if (t)
		len = scnprintf(buf, sizeof(buf), "%pM\n", t->mac);
	else
		len = scnprintf(buf, sizeof(buf), "none\n");
	rcu_read_unlock();

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

/*
 * A unicast MAC as six colon-separated hex pairs, or "none"; each with
 * at most one newline after it.
 */
static ssize_t u6e_pcc_target_write(struct file *file, const char __user *ubuf,
				    size_t count, loff_t *ppos)
{
	char buf[MAC_ADDR_STR_LEN + 2];
	u8 mac[ETH_ALEN];
	int ret;

	ret = u6e_pcc_write_line(buf, sizeof(buf), ubuf, count, ppos);
	if (ret)
		return ret;

	mutex_lock(&u6e_pcc_lock);
	if (!strcmp(buf, "none"))
		ret = u6e_pcc_set(NULL, true);
	else if (strlen(buf) == MAC_ADDR_STR_LEN && mac_pton(buf, mac) &&
		 is_valid_ether_addr(mac))
		ret = u6e_pcc_set(mac, true);
	else
		ret = -EINVAL;
	mutex_unlock(&u6e_pcc_lock);

	return ret ? ret : count;
}

static const struct file_operations u6e_pcc_target_fops = {
	.owner = THIS_MODULE,
	.read = u6e_pcc_target_read,
	.write = u6e_pcc_target_write,
	.llseek = default_llseek,
};

static ssize_t u6e_pcc_snaplen_read(struct file *file, char __user *ubuf,
				    size_t count, loff_t *ppos)
{
	char buf[8];
	int len;

	mutex_lock(&u6e_pcc_lock);
	len = scnprintf(buf, sizeof(buf), "%u\n", u6e_pcc_snaplen);
	mutex_unlock(&u6e_pcc_lock);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

/*
 * Decimal bytes, at least U6E_PCC_SNAPLEN_MIN (an Ethernet, IPv6 and TCP
 * header with options fit); the mirror applies it from the next target.
 */
static ssize_t u6e_pcc_snaplen_write(struct file *file, const char __user *ubuf,
				     size_t count, loff_t *ppos)
{
	char buf[8];
	u16 snaplen;
	int ret;

	ret = u6e_pcc_write_line(buf, sizeof(buf), ubuf, count, ppos);
	if (ret)
		return ret;
	if (kstrtou16(buf, 10, &snaplen) || snaplen < U6E_PCC_SNAPLEN_MIN)
		return -EINVAL;

	mutex_lock(&u6e_pcc_lock);
	if (rcu_access_pointer(u6e_pcc_target))
		ret = -EBUSY;
	else
		u6e_pcc_snaplen = snaplen;
	mutex_unlock(&u6e_pcc_lock);

	return ret ? ret : count;
}

static const struct file_operations u6e_pcc_snaplen_fops = {
	.owner = THIS_MODULE,
	.read = u6e_pcc_snaplen_read,
	.write = u6e_pcc_snaplen_write,
	.llseek = default_llseek,
};

/*
 * Drop the target when the mirror netdev goes away, which would otherwise
 * wait forever for the reference held on it.
 */
static int u6e_pcc_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	mutex_lock(&u6e_pcc_lock);
	if (dev == u6e_pcc_mirror_dev)
		u6e_pcc_set(NULL, false);
	mutex_unlock(&u6e_pcc_lock);

	return NOTIFY_DONE;
}

static struct notifier_block u6e_pcc_netdev_nb = {
	.notifier_call = u6e_pcc_netdev_event,
};

static int __init u6e_pcc_init(void)
{
	int ret;

	/* KBUILD_MODNAME is u6e_pcc; the files are documented as u6e-pcc. */
	u6e_pcc_dir = debugfs_create_dir("u6e-pcc", NULL);
	if (IS_ERR(u6e_pcc_dir))
		return PTR_ERR(u6e_pcc_dir);
	debugfs_create_file("target", 0600, u6e_pcc_dir, NULL, &u6e_pcc_target_fops);
	debugfs_create_file("snaplen", 0600, u6e_pcc_dir, NULL, &u6e_pcc_snaplen_fops);

	ret = register_netdevice_notifier(&u6e_pcc_netdev_nb);
	if (ret)
		goto err_debugfs;

	ret = ecm_classifier_pcc_register(&u6e_pcc_registrant);
	if (ret)
		goto err_notifier;

	/* ECM holds its own reference now; drop the initial one. */
	u6e_pcc_registrant.deref(&u6e_pcc_registrant);

	return 0;

err_notifier:
	unregister_netdevice_notifier(&u6e_pcc_netdev_nb);
err_debugfs:
	debugfs_remove(u6e_pcc_dir);
	return ret;
}
module_init(u6e_pcc_init);

MODULE_DESCRIPTION("Mirror one client's offloaded TCP and UDP flows through ECM's PCC and NSS");
MODULE_LICENSE("GPL");
