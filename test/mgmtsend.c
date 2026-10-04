/* mgmtsend <ifname> <dst-mac> <probe|action> <count>: send unicast management
 * frames with NL80211_CMD_FRAME and print the time to each TX status, which
 * grows with the number of retries when nothing ACKs. */
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define NLA_A(n) (((n) + 3) & ~3)
static int fd, fam, mlme;
static unsigned char buf[16384];

static struct nlattr *put(struct nlmsghdr *h, int type, const void *d, int len)
{
	struct nlattr *a = (void *)((char *)h + NLA_A(h->nlmsg_len));
	a->nla_type = type; a->nla_len = NLA_HDRLEN + len;
	memcpy((char *)a + NLA_HDRLEN, d, len);
	h->nlmsg_len = NLA_A(h->nlmsg_len) + NLA_A(a->nla_len);
	return a;
}

static struct nlmsghdr *msg(int type, int cmd)
{
	static unsigned char m[4096];
	struct nlmsghdr *h = (void *)m;
	struct genlmsghdr *g = NLMSG_DATA(h);
	memset(m, 0, sizeof(m));
	h->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN); h->nlmsg_type = type;
	h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK; g->cmd = cmd; g->version = 1;
	return h;
}

static double now(void)
{
	struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

/* Walk attributes of a genl message; cb gets each top-level attribute. */
#define FOR_ATTR(h, a) for (struct nlattr *a = (void *)((char *)NLMSG_DATA(h) + GENL_HDRLEN); \
	(char *)a < (char *)h + h->nlmsg_len && a->nla_len >= NLA_HDRLEN; a = (void *)((char *)a + NLA_A(a->nla_len)))

static void resolve(void)
{
	struct nlmsghdr *h = msg(GENL_ID_CTRL, CTRL_CMD_GETFAMILY);
	put(h, CTRL_ATTR_FAMILY_NAME, "nl80211", 8);
	send(fd, h, h->nlmsg_len, 0);
	int n = recv(fd, buf, sizeof(buf), 0);
	for (struct nlmsghdr *r = (void *)buf; NLMSG_OK(r, n); r = NLMSG_NEXT(r, n)) {
		if (r->nlmsg_type != GENL_ID_CTRL) continue;
		FOR_ATTR(r, a) {
			if (a->nla_type == CTRL_ATTR_FAMILY_ID) fam = *(uint16_t *)((char *)a + NLA_HDRLEN);
			if ((a->nla_type & 0x7fff) != CTRL_ATTR_MCAST_GROUPS) continue;
			for (struct nlattr *g = (void *)((char *)a + NLA_HDRLEN); (char *)g < (char *)a + a->nla_len; g = (void *)((char *)g + NLA_A(g->nla_len))) {
				int id = 0; const char *name = "";
				for (struct nlattr *f = (void *)((char *)g + NLA_HDRLEN); (char *)f < (char *)g + g->nla_len; f = (void *)((char *)f + NLA_A(f->nla_len))) {
					if (f->nla_type == CTRL_ATTR_MCAST_GRP_ID) id = *(uint32_t *)((char *)f + NLA_HDRLEN);
					if (f->nla_type == CTRL_ATTR_MCAST_GRP_NAME) name = (char *)f + NLA_HDRLEN;
				}
				if (!strcmp(name, "mlme")) mlme = id;
			}
		}
	}
	recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
}

int main(int argc, char **argv)
{
	unsigned char f[128], da[6], sa[6];
	struct ifreq ifr = {0};
	int ifindex, len, count, probe;

	if (argc != 5) { fprintf(stderr, "usage: mgmtsend <ifname> <dst-mac> <probe|action> <count>\n"); return 2; }
	ifindex = if_nametoindex(argv[1]);
	sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &da[0], &da[1], &da[2], &da[3], &da[4], &da[5]);
	probe = !strcmp(argv[3], "probe"); count = atoi(argv[4]);
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1); ioctl(s, SIOCGIFHWADDR, &ifr); close(s);
	memcpy(sa, ifr.ifr_hwaddr.sa_data, 6);

	memset(f, 0, sizeof(f));
	f[0] = probe ? 0x50 : 0xd0;
	memcpy(f + 4, da, 6); memcpy(f + 10, sa, 6); memcpy(f + 16, sa, 6);
	len = 24;
	if (probe) {	/* timestamp, beacon interval 100, ESS, SSID "x" */
		len += 8; f[len++] = 100; f[len++] = 0; f[len++] = 0x01; f[len++] = 0;
		f[len++] = 0; f[len++] = 1; f[len++] = 'x';
	} else {	/* Public Action, 20/40 BSS Coexistence, no fields set */
		f[len++] = 4; f[len++] = 0; f[len++] = 72; f[len++] = 1; f[len++] = 0;
	}

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	resolve();
	if (!fam || !mlme) { fprintf(stderr, "nl80211 not found\n"); return 1; }
	setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &mlme, sizeof(mlme));

	int acked = 0; double sum = 0, mx = 0, mn = 1e9;
	for (int i = 0; i < count; i++) {
		struct nlmsghdr *h = msg(fam, NL80211_CMD_FRAME);
		uint64_t cookie = 0; double t0 = now(), t1 = 0; int ack = 0;
		put(h, NL80211_ATTR_IFINDEX, &ifindex, 4);
		put(h, NL80211_ATTR_FRAME, f, len);
		send(fd, h, h->nlmsg_len, 0);
		while (now() - t0 < 1000 && !t1) {
			int n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
			if (n <= 0) { usleep(50); continue; }
			for (struct nlmsghdr *r = (void *)buf; NLMSG_OK(r, n); r = NLMSG_NEXT(r, n)) {
				if (r->nlmsg_type == NLMSG_ERROR) {
					struct nlmsgerr *e = NLMSG_DATA(r);
					if (e->error) { fprintf(stderr, "CMD_FRAME: %s\n", strerror(-e->error)); return 1; }
					continue;
				}
				if (r->nlmsg_type != fam) continue;
				struct genlmsghdr *g = NLMSG_DATA(r);
				uint64_t c = 0; int a_ack = 0;
				FOR_ATTR(r, a) {
					if (a->nla_type == NL80211_ATTR_COOKIE) memcpy(&c, (char *)a + NLA_HDRLEN, 8);
					if (a->nla_type == NL80211_ATTR_ACK) a_ack = 1;
				}
				if (g->cmd == NL80211_CMD_FRAME) cookie = c;
				else if (g->cmd == NL80211_CMD_FRAME_TX_STATUS && cookie && c == cookie) { t1 = now(); ack = a_ack; }
			}
		}
		if (!t1) { printf("frame %d: no tx status\n", i); continue; }
		double d = t1 - t0; sum += d; acked += ack;
		if (d > mx) mx = d; if (d < mn) mn = d;
		usleep(20000);
	}
	printf("%s x%d: acked %d, tx-status ms min %.2f avg %.2f max %.2f\n", argv[3], count, acked, mn, sum / count, mx);
	return 0;
}
