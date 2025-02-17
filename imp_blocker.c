#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <net/pfil.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* Global counters for dropped ICMP packets */
static int icmp_drop_count = 0;
static int icmp_drop_bytes = 0;

/* 
 * Hook function: called for every IPv4 packet on the inbound path.
 * If the packet is an ICMP Echo Request, log and drop it.
 */
static int
icmp_hook(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, struct inpcb *inp)
{
    struct ip *ip_hdr;
    struct icmp *icmp_hdr;

    if (*mp == NULL)
        return 0;

    /* Ensure the mbuf has at least an IP header */
    if ((*mp)->m_len < sizeof(struct ip))
        return 0;
    ip_hdr = mtod(*mp, struct ip *);

    if (ip_hdr->ip_v != 4 || ip_hdr->ip_p != IPPROTO_ICMP)
        return 0;

    /* Make sure the mbuf contains the entire ICMP header */
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

/*
 * Global hook argument structure.
 * Fill it in during module load.
 */
static struct pfil_hook_args pha;

static int
icmp_blocker_modevent(module_t mod, int event, void *arg)
{
    int error = 0;

    switch (event) {
    case MOD_LOAD:
        /* Zero out the structure and fill in the required fields */
        memset(&pha, 0, sizeof(pha));
        pha.pfh_type = PFIL_IN;       /* Hook on incoming packets */
        pha.af = AF_INET;             /* For IPv4 */
        pha.func = icmp_hook;         /* Our hook function */
        pha.arg = NULL;               /* No extra arguments */

        error = pfil_add_hook(&pha);
        if (error != 0) {
            printf("Diamond Shield: pfil_add_hook failed with error %d\n", error);
            return error;
        }
        printf("Diamond Shield: ICMP blocker module loaded.\n");
        break;

    case MOD_UNLOAD:
        error = pfil_remove_hook(&pha);
        if (error != 0) {
            printf("Diamond Shield: pfil_remove_hook failed with error %d\n", error);
            return error;
        }
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
    "icmp_blocker",          /* Module name */
    icmp_blocker_modevent,   /* Event handler */
    NULL
};

DECLARE_MODULE(icmp_blocker, icmp_blocker_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(icmp_blocker, 1);
