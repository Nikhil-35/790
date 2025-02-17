#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <net/if.h>
#include <net/pfil.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

static int icmp_drop_count = 0;
static int icmp_drop_bytes = 0;

/*
 * Hook function that is called for every IP packet.
 * 'dir' indicates PFIL_IN for inbound packets.
 */
static int
my_hook(void *arg, struct mbuf **mp, int dir, struct ifnet *ifp, int ruleset)
{
    struct ip *ip;

    if (mp == NULL || *mp == NULL)
        return 0;

    /* We only process inbound packets */
    if (dir != PFIL_IN)
        return 0;

    ip = mtod(*mp, struct ip *);

    if (ip->ip_p == IPPROTO_ICMP) {
        struct icmp *icmp = (struct icmp *)((char *)ip + (ip->ip_hl << 2));
        if (icmp->icmp_type == ICMP_ECHO) {
            /* Update counters */
            icmp_drop_count++;
            icmp_drop_bytes += (*mp)->m_pkthdr.len;
            /* Print a message to the console */
            printf("my_icmp_filter: Dropping ICMP Echo (size %d bytes)\n",
                   (*mp)->m_pkthdr.len);
            /* Drop the packet */
            m_freem(*mp);
            *mp = NULL;
            return PFIL_DROPPED;
        }
    }

    /*
     * For a simpler version that does nothing but print a message on every packet,
     * you could uncomment the following:
     *
     * printf("my_icmp_filter: Hello world, packet received (len %d bytes)\n",
     *        (*mp)->m_pkthdr.len);
     *
     * and then simply return 0.
     */

    return 0;
}

static struct pfil_head *pfil_hook_head;

static int
my_module_event(module_t mod, int what, void *arg)
{
    int error = 0;

    switch (what) {
    case MOD_LOAD:
        /* Get the pfil head for IPv4 */
        pfil_hook_head = pfil_head_get(PFIL_TYPE_IP, 0);
        if (pfil_hook_head == NULL) {
            error = ENOENT;
            break;
        }
        error = pfil_add_hook(my_hook, NULL, PFIL_IN, pfil_hook_head);
        if (error == 0)
            printf("my_icmp_filter: Module loaded – dropping ICMP echo requests.\n");
        break;

    case MOD_UNLOAD:
        if (pfil_hook_head != NULL)
            pfil_remove_hook(my_hook, NULL, PFIL_IN, pfil_hook_head);
        printf("my_icmp_filter: Module unloaded – dropped %d ICMP echo requests (%d bytes).\n",
               icmp_drop_count, icmp_drop_bytes);
        break;

    default:
        error = EOPNOTSUPP;
        break;
    }
    return error;
}

static moduledata_t my_moddata = {
    "my_icmp_filter",  /* module name */
    my_module_event,   /* event handler */
    NULL
};

DECLARE_MODULE(my_icmp_filter, my_moddata, SI_SUB_PFIL, SI_ORDER_ANY);
MODULE_VERSION(my_icmp_filter, 1);
