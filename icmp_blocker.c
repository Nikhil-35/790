#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <net/pfil.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

static int icmp_drop_count = 0;
static int icmp_drop_bytes = 0;

/* This hook function inspects each IPv4 packet on the inbound path.
 * If it finds an ICMP Echo Request, it increments counters, prints a log,
 * frees the packet, and instructs the stack not to process it further.
 */
static int
icmp_hook(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, struct inpcb *inp)
{
    struct ip *ip_hdr;
    struct icmp *icmp_hdr;

    if (*mp == NULL)
        return 0;

    /* Ensure we have enough data for an IP header */
    if ((*mp)->m_len < sizeof(struct ip))
        return 0;
    ip_hdr = mtod(*mp, struct ip *);

    /* Process only IPv4 ICMP packets */
    if (ip_hdr->ip_v != 4 || ip_hdr->ip_p != IPPROTO_ICMP)
        return 0;

    /* Ensure we have enough data for the ICMP header */
    if ((*mp)->m_len < (ip_hdr->ip_hl << 2) + sizeof(struct icmp))
        return 0;
    icmp_hdr = (struct icmp *)((char *)ip_hdr + (ip_hdr->ip_hl << 2));

    if (icmp_hdr->icmp_type == ICMP_ECHO) {
        icmp_drop_count++;
        icmp_drop_bytes += (*mp)->m_pkthdr.len;
        printf("Diamond Shield: Dropped ICMP Echo Request #%d, size %d bytes\n",
               icmp_drop_count, (*mp)->m_pkthdr.len);
        m_freem(*mp);
        *mp = NULL;
        return (EJUSTRETURN);
    }

    return 0;
}

static struct pfil_head *pfh_inet = NULL;

static int
icmp_blocker_modevent(module_t mod, int event, void *arg)
{
    int error = 0;

    switch (event) {
    case MOD_LOAD:
        pfh_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
        if (pfh_inet == NULL) {
            printf("Diamond Shield: Failed to get pfil head for AF_INET\n");
            return (ENOENT);
        }
        error = pfil_add_hook(icmp_hook, NULL, PFIL_IN, pfh_inet);
        if (error != 0) {
            printf("Diamond Shield: pfil_add_hook failed\n");
            return error;
        }
        printf("Diamond Shield: ICMP blocker module loaded.\n");
        break;

    case MOD_UNLOAD:
        if (pfh_inet != NULL)
            pfil_remove_hook(icmp_hook, NULL, PFIL_IN, pfh_inet);
        printf("Diamond Shield: ICMP blocker module unloaded. Total dropped: %d packets, %d bytes\n",
               icmp_drop_count, icmp_drop_bytes);
        break;

    default:
        error = EOPNOTSUPP;
        break;
    }
    return error;
}

static moduledata_t icmp_blocker_mod = {
    "icmp_blocker",  /* Module name */
    icmp_blocker_modevent, /* Event handler */
    NULL
};

DECLARE_MODULE(icmp_blocker, icmp_blocker_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(icmp_blocker, 1);
