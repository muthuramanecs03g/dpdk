/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_flow.h>
#include <rte_gtp.h>

#include "testpmd.h"

struct tx_timestamp {
	rte_be32_t signature;
	rte_be16_t pkt_idx;
	rte_be16_t queue_idx;
	rte_be64_t ts;
};

__extension__
struct gtp_psc_hdr {
	uint8_t ext_hdr_len;	/**< PDU ext hdr len in multiples of 4 bytes */
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint8_t type:4;		/**< PDU type */
	uint8_t qmp:1;		/**< Qos Monitoring Packet */
	uint8_t pad:3;		/**< type specific pad bits */
	uint8_t spare:2;	/**< type specific spare bits */
	uint8_t qfi:6;		/**< Qos Flow Identifier */
#else
	uint8_t qfi:6;		/**< Qos Flow Identifier */
	uint8_t spare:2;	/**< type specific spare bits */
	uint8_t pad:3;		/**< type specific pad bits */
	uint8_t qmp:1;		/**< Qos Monitoring Packet */
	uint8_t type:4;		/**< PDU type */
#endif
	uint8_t nxt_ext;
} __rte_packed;

struct gtpu_hdr {
    uint8_t   version_flags;
    uint8_t   type;
    uint16_t  length;
    uint32_t  teid;
} __rte_packed;

struct gtpu_ext_hdr {
    uint16_t  seq_num;
    uint8_t   npdu_num;
    uint8_t   nxt_ext_hdr;
} __rte_packed;

struct gtpu_pdu_sess_ctr {
    uint8_t length;
    uint8_t type;
    uint8_t qfi;
    uint8_t nxt_ext_hdr;
} __rte_packed;

struct pkt_ul_hdr {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#else
    struct rte_ether_hdr        eth;
    struct rte_ipv4_hdr         ipv4;
    struct rte_udp_hdr          udp;
    struct gtpu_hdr             gtpu;
    struct gtpu_ext_hdr         gtpu_ext;
    struct gtpu_pdu_sess_ctr    pdu_sess_ctr;
    struct rte_ipv4_hdr         in_ipv4;
    struct rte_udp_hdr          in_udp;
#endif
} __rte_packed;


/* use RFC863 Discard Protocol */
uint16_t tx_udp_src_port = 9;
uint16_t tx_udp_dst_port = 9;

// GTP-U port
uint16_t tx_udp_gtp_port = 2152;

/* use RFC5735 / RFC2544 reserved network test addresses */
uint32_t tx_ip_src_addr = (198U << 24) | (18 << 16) | (0 << 8) | 1;
uint32_t tx_ip_dst_addr = (198U << 24) | (18 << 16) | (0 << 8) | 2;

// Out IP for gNB -> UPF, In for UE -> DN
uint32_t tx_ip_src_out_addr = (30 << 24) | (30 << 16) | (0 << 8) | 2;
uint32_t tx_ip_dst_out_addr = (30 << 24) | (30 << 16) | (0 << 8) | 3;
uint32_t tx_ip_src_in_addr = (10 << 24) | (60 << 16) | (0 << 8) | 1;
uint32_t tx_ip_dst_in_addr = (8 << 24) | (8 << 16) | (8 << 8) | 2;

#define IP_DEFTTL  64   /* from RFC 1340. */

static struct rte_ipv4_hdr pkt_ip_hdr; /**< IP header of transmitted packets. */
RTE_DEFINE_PER_LCORE(uint8_t, _ip_var); /**< IP address variation */
static struct rte_udp_hdr pkt_udp_hdr; /**< UDP header of tx packets. */

RTE_DEFINE_PER_LCORE(uint64_t, timestamp_qskew);
					/**< Timestamp offset per queue */
RTE_DEFINE_PER_LCORE(uint32_t, timestamp_idone); /**< Timestamp init done. */

static uint64_t timestamp_mask; /**< Timestamp dynamic flag mask */
static int32_t timestamp_off; /**< Timestamp dynamic field offset */
static bool timestamp_enable; /**< Timestamp enable */
static uint32_t timestamp_init_req; /**< Timestamp initialization request. */
static uint64_t timestamp_initial[RTE_MAX_ETHPORTS];


#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

struct pkt_ul_hdr  pkt_ul;

static void
copy_buf_to_pkt_segs(void* buf, unsigned len, struct rte_mbuf *pkt,
		     unsigned offset)
{
	struct rte_mbuf *seg;
	void *seg_buf;
	unsigned copy_len;

	seg = pkt;
	while (offset >= seg->data_len) {
		offset -= seg->data_len;
		seg = seg->next;
	}
	copy_len = seg->data_len - offset;
	seg_buf = rte_pktmbuf_mtod_offset(seg, char *, offset);
	while (len > copy_len) {
		rte_memcpy(seg_buf, buf, (size_t) copy_len);
		len -= copy_len;
		buf = ((char*) buf + copy_len);
		seg = seg->next;
		seg_buf = rte_pktmbuf_mtod(seg, char *);
		copy_len = seg->data_len;
	}
	rte_memcpy(seg_buf, buf, (size_t) len);
}

static inline void
copy_buf_to_pkt(void* buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset),
			buf, (size_t) len);
		return;
	}
	copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

static void
setup_pkt_gtpu_headers(uint16_t pkt_data_len) {
	uint16_t pkt_len;

	pkt_len = pkt_data_len + 8; // Inner-UDP + Data
	pkt_ul.in_udp.src_port = rte_cpu_to_be_16(1234);
	pkt_ul.in_udp.dst_port = rte_cpu_to_be_16(4321);
	pkt_ul.in_udp.dgram_len = rte_cpu_to_be_16(pkt_len);
	
	pkt_len += 20; // Inner-IP
	pkt_ul.in_ipv4.version_ihl = IP_VHL_DEF;
	pkt_ul.in_ipv4.type_of_service = 0;   
	pkt_ul.in_ipv4.total_length = rte_cpu_to_be_16(pkt_len);      
	pkt_ul.in_ipv4.packet_id = 0;     
	pkt_ul.in_ipv4.fragment_offset = 0;   
	pkt_ul.in_ipv4.time_to_live = IP_DEFTTL;      
	pkt_ul.in_ipv4.next_proto_id = IPPROTO_UDP;     
	pkt_ul.in_ipv4.hdr_checksum = 0;      
	pkt_ul.in_ipv4.src_addr = rte_cpu_to_be_32(0x0a3c0001);      
	pkt_ul.in_ipv4.dst_addr = rte_cpu_to_be_32(0x0a3c00fe);

	pkt_ul.pdu_sess_ctr.length = 1;
	pkt_ul.pdu_sess_ctr.type = 0x10;
	pkt_ul.pdu_sess_ctr.qfi = 0x09;
	pkt_ul.pdu_sess_ctr.nxt_ext_hdr = 0;
	pkt_ul.gtpu_ext.seq_num = rte_cpu_to_be_16(0);
	pkt_ul.gtpu_ext.npdu_num = 0;
	pkt_ul.gtpu_ext.nxt_ext_hdr = 0x85;
	pkt_len += 8; // GTP-U Extension header + PDU Session Container

	pkt_ul.gtpu.version_flags = 0x34;
	pkt_ul.gtpu.type = 0xff;
	pkt_ul.gtpu.length = rte_cpu_to_be_16(pkt_len);
	pkt_ul.gtpu.teid = rte_cpu_to_be_32(0x01);
	pkt_len += 8; // GTP-U header

	pkt_len += 8; // Outer UDP header
	pkt_ul.udp.src_port = rte_cpu_to_be_16(9);
	pkt_ul.udp.dst_port = rte_cpu_to_be_16(9);
	pkt_ul.udp.dgram_len = rte_cpu_to_be_16(pkt_len);
	
	pkt_len += 20; // Outer-IP header
	pkt_ul.ipv4.version_ihl = IP_VHL_DEF;
	pkt_ul.ipv4.type_of_service = 0;   
	pkt_ul.ipv4.total_length = rte_cpu_to_be_16(pkt_len);      
	pkt_ul.ipv4.packet_id = 0;     
	pkt_ul.ipv4.fragment_offset = 0;   
	pkt_ul.ipv4.time_to_live = IP_DEFTTL;      
	pkt_ul.ipv4.next_proto_id = IPPROTO_UDP;     
	pkt_ul.ipv4.hdr_checksum = 0;      
	pkt_ul.ipv4.src_addr = rte_cpu_to_be_32(0x1e1e0002);      
	pkt_ul.ipv4.dst_addr = rte_cpu_to_be_32(0x1e1e0003);
	printf("Muthu Total IP Length: %d\n", pkt_len);	
}

static void dump_mbuf(struct pkt_ul_hdr *data) {
	char *ch = (char *) data;
	for (int i = 0; i < 32; i++) {
		printf(" %x", ch[i]);
	}
	printf("\n");
}

static void
setup_pkt_udp_ip_headers(struct rte_ipv4_hdr *ip_hdr,
	struct rte_udp_hdr *udp_hdr,
	uint16_t pkt_data_len)
{
	uint16_t *ptr16;
	uint32_t ip_cksum;
	uint16_t pkt_len;

	/*
	 * Initialize UDP header.
	 */
	pkt_len = (uint16_t) (pkt_data_len + sizeof(struct rte_udp_hdr));
	udp_hdr->src_port = rte_cpu_to_be_16(tx_udp_src_port);
	udp_hdr->dst_port = rte_cpu_to_be_16(tx_udp_dst_port);
	udp_hdr->dgram_len      = RTE_CPU_TO_BE_16(pkt_len);
	udp_hdr->dgram_cksum    = 0; /* No UDP checksum. */

	/*
	 * Initialize IP header.
	 */
	pkt_len = (uint16_t) (pkt_len + sizeof(struct rte_ipv4_hdr));
	ip_hdr->version_ihl   = RTE_IPV4_VHL_DEF;
	ip_hdr->type_of_service   = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live   = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length   = RTE_CPU_TO_BE_16(pkt_len);
	ip_hdr->src_addr = rte_cpu_to_be_32(tx_ip_src_addr);
	ip_hdr->dst_addr = rte_cpu_to_be_32(tx_ip_dst_addr);

	/*
	 * Compute IP header checksum.
	 */
	ptr16 = (unaligned_uint16_t*) ip_hdr;
	ip_cksum = 0;
	ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
	ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
	ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

	/*
	 * Reduce 32 bit checksum to 16 bits and complement it.
	 */
	ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
		(ip_cksum & 0x0000FFFF);
	if (ip_cksum > 65535)
		ip_cksum -= 65535;
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
	ip_hdr->hdr_checksum = (uint16_t) ip_cksum;
}

static inline void
update_pkt_header(struct rte_mbuf *pkt, uint32_t total_pkt_len)
{
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint16_t pkt_data_len;
	uint16_t pkt_len;

	pkt_data_len = (uint16_t) (total_pkt_len - (
					sizeof(struct rte_ether_hdr) +
					sizeof(struct rte_ipv4_hdr) +
					sizeof(struct rte_udp_hdr)));
	/* updata udp pkt length */
	udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *,
				sizeof(struct rte_ether_hdr) +
				sizeof(struct rte_ipv4_hdr));
	pkt_len = (uint16_t) (pkt_data_len + sizeof(struct rte_udp_hdr));
	udp_hdr->dgram_len = RTE_CPU_TO_BE_16(pkt_len);

	/* updata ip pkt length and csum */
	ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
	ip_hdr->hdr_checksum = 0;
	pkt_len = (uint16_t) (pkt_len + sizeof(struct rte_ipv4_hdr));
	ip_hdr->total_length = RTE_CPU_TO_BE_16(pkt_len);
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
}

static inline bool
pkt_burst_prepare_gtpu(struct rte_mbuf *pkt, struct rte_mempool *mbp,
		struct rte_ether_hdr *eth_hdr, const uint16_t vlan_tci,
		const uint16_t vlan_tci_outer, const uint64_t ol_flags,
		const uint16_t idx, const struct fwd_stream *fs)
{
	struct rte_mbuf *pkt_segs[RTE_MAX_SEGS_PER_PKT];
	struct rte_mbuf *pkt_seg;
	uint32_t nb_segs, pkt_len;
	uint8_t i;

	if (unlikely(tx_pkt_split == TX_PKT_SPLIT_RND))
		nb_segs = rte_rand() % tx_pkt_nb_segs + 1;
	else
		nb_segs = tx_pkt_nb_segs;

	if (nb_segs > 1) {
		if (rte_mempool_get_bulk(mbp, (void **)pkt_segs, nb_segs - 1))
			return false;
	}

	rte_pktmbuf_reset_headroom(pkt);
	pkt->data_len = tx_pkt_seg_lengths[0];
	pkt->ol_flags &= RTE_MBUF_F_EXTERNAL;
	pkt->ol_flags |= ol_flags;
	pkt->vlan_tci = vlan_tci;
	pkt->vlan_tci_outer = vlan_tci_outer;
	pkt->l2_len = sizeof(struct rte_ether_hdr);
	pkt->l3_len = sizeof(struct rte_ipv4_hdr);
	pkt->l4_len = sizeof(struct rte_udp_hdr);

	pkt_len = pkt->data_len;
	pkt_seg = pkt;
	for (i = 1; i < nb_segs; i++) {
		pkt_seg->next = pkt_segs[i - 1];
		pkt_seg = pkt_seg->next;
		pkt_seg->data_len = tx_pkt_seg_lengths[i];
		pkt_len += pkt_seg->data_len;
	}
	pkt_seg->next = NULL; /* Last segment of packet. */

	rte_memcpy(&pkt_ul.eth, eth_hdr, sizeof(*eth_hdr));
	struct pkt_ul_hdr *data = rte_pktmbuf_mtod(pkt, struct pkt_ul_hdr *);
    rte_memcpy((void *)data, (void *) &pkt_ul, 86);
	// dump_mbuf(data);
	rte_wmb();

	/*
	 * Complete first mbuf of packet and append it to the
	 * burst of packets to be transmitted.
	 */
	pkt->nb_segs = nb_segs;
	pkt->pkt_len = pkt_len;
	return true;
}

static inline bool
pkt_burst_prepare(struct rte_mbuf *pkt, struct rte_mempool *mbp,
		struct rte_ether_hdr *eth_hdr, const uint16_t vlan_tci,
		const uint16_t vlan_tci_outer, const uint64_t ol_flags,
		const uint16_t idx, const struct fwd_stream *fs)
{
	struct rte_mbuf *pkt_segs[RTE_MAX_SEGS_PER_PKT];
	struct rte_mbuf *pkt_seg;
	uint32_t nb_segs, pkt_len;
	uint8_t i;

	if (unlikely(tx_pkt_split == TX_PKT_SPLIT_RND))
		nb_segs = rte_rand() % tx_pkt_nb_segs + 1;
	else
		nb_segs = tx_pkt_nb_segs;

	if (nb_segs > 1) {
		if (rte_mempool_get_bulk(mbp, (void **)pkt_segs, nb_segs - 1))
			return false;
	}

	rte_pktmbuf_reset_headroom(pkt);
	pkt->data_len = tx_pkt_seg_lengths[0];
	pkt->ol_flags &= RTE_MBUF_F_EXTERNAL;
	pkt->ol_flags |= ol_flags;
	pkt->vlan_tci = vlan_tci;
	pkt->vlan_tci_outer = vlan_tci_outer;
	pkt->l2_len = sizeof(struct rte_ether_hdr);
	pkt->l3_len = sizeof(struct rte_ipv4_hdr);

	pkt_len = pkt->data_len;
	pkt_seg = pkt;
	for (i = 1; i < nb_segs; i++) {
		pkt_seg->next = pkt_segs[i - 1];
		pkt_seg = pkt_seg->next;
		pkt_seg->data_len = tx_pkt_seg_lengths[i];
		pkt_len += pkt_seg->data_len;
	}
	pkt_seg->next = NULL; /* Last segment of packet. */
	/*
	 * Copy headers in first packet segment(s).
	 */
	copy_buf_to_pkt(eth_hdr, sizeof(*eth_hdr), pkt, 0);
	copy_buf_to_pkt(&pkt_ip_hdr, sizeof(pkt_ip_hdr), pkt,
			sizeof(struct rte_ether_hdr));
	if (txonly_multi_flow) {
		uint8_t  ip_var = RTE_PER_LCORE(_ip_var);
		struct rte_ipv4_hdr *ip_hdr;
		uint32_t addr;

		ip_hdr = rte_pktmbuf_mtod_offset(pkt,
				struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
		/*
		 * Generate multiple flows by varying IP src addr. This
		 * enables packets are well distributed by RSS in
		 * receiver side if any and txonly mode can be a decent
		 * packet generator for developer's quick performance
		 * regression test.
		 */
		addr = (tx_ip_dst_addr | (ip_var++ << 8)) + rte_lcore_id();
		ip_hdr->src_addr = rte_cpu_to_be_32(addr);
		RTE_PER_LCORE(_ip_var) = ip_var;
	}
	copy_buf_to_pkt(&pkt_udp_hdr, sizeof(pkt_udp_hdr), pkt,
			sizeof(struct rte_ether_hdr) +
			sizeof(struct rte_ipv4_hdr));

	if (unlikely(tx_pkt_split == TX_PKT_SPLIT_RND) || txonly_multi_flow)
		update_pkt_header(pkt, pkt_len);

	if (unlikely(timestamp_enable)) {
		uint64_t skew = RTE_PER_LCORE(timestamp_qskew);
		struct tx_timestamp timestamp_mark;

		if (unlikely(timestamp_init_req !=
				RTE_PER_LCORE(timestamp_idone))) {
			struct rte_eth_dev_info dev_info;
			unsigned int txqs_n;
			uint64_t phase;
			int ret;

			ret = eth_dev_info_get_print_err(fs->tx_port, &dev_info);
			if (ret != 0) {
				TESTPMD_LOG(ERR,
					"Failed to get device info for port %d,"
					"could not finish timestamp init",
					fs->tx_port);
				return false;
			}
			txqs_n = dev_info.nb_tx_queues;
			phase = tx_pkt_times_inter * fs->tx_queue /
					 (txqs_n ? txqs_n : 1);
			/*
			 * Initialize the scheduling time phase shift
			 * depending on queue index.
			 */
			skew = timestamp_initial[fs->tx_port] +
			       tx_pkt_times_inter + phase;
			RTE_PER_LCORE(timestamp_qskew) = skew;
			RTE_PER_LCORE(timestamp_idone) = timestamp_init_req;
		}
		timestamp_mark.pkt_idx = rte_cpu_to_be_16(idx);
		timestamp_mark.queue_idx = rte_cpu_to_be_16(fs->tx_queue);
		timestamp_mark.signature = rte_cpu_to_be_32(0xBEEFC0DE);
		if (unlikely(!idx)) {
			skew +=	tx_pkt_times_inter;
			pkt->ol_flags |= timestamp_mask;
			*RTE_MBUF_DYNFIELD
				(pkt, timestamp_off, uint64_t *) = skew;
			RTE_PER_LCORE(timestamp_qskew) = skew;
			timestamp_mark.ts = rte_cpu_to_be_64(skew);
		} else if (tx_pkt_times_intra) {
			skew +=	tx_pkt_times_intra;
			pkt->ol_flags |= timestamp_mask;
			*RTE_MBUF_DYNFIELD
				(pkt, timestamp_off, uint64_t *) = skew;
			RTE_PER_LCORE(timestamp_qskew) = skew;
			timestamp_mark.ts = rte_cpu_to_be_64(skew);
		} else {
			timestamp_mark.ts = RTE_BE64(0);
		}
		copy_buf_to_pkt(&timestamp_mark, sizeof(timestamp_mark), pkt,
			sizeof(struct rte_ether_hdr) +
			sizeof(struct rte_ipv4_hdr) +
			sizeof(pkt_udp_hdr));
	}
	/*
	 * Complete first mbuf of packet and append it to the
	 * burst of packets to be transmitted.
	 */
	pkt->nb_segs = nb_segs;
	pkt->pkt_len = pkt_len;

	return true;
}

/*
 * Transmit a burst of multi-segments packets.
 */
static void
pkt_burst_transmit(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_port *txp;
	struct rte_mbuf *pkt;
	struct rte_mempool *mbp;
	struct rte_ether_hdr eth_hdr;
	uint16_t nb_tx;
	uint16_t nb_pkt;
	uint16_t vlan_tci, vlan_tci_outer;
	uint32_t retry;
	uint64_t ol_flags = 0;
	uint64_t tx_offloads;
	uint64_t start_tsc = 0;

	get_start_cycles(&start_tsc);

	mbp = current_fwd_lcore()->mbp;
	txp = &ports[fs->tx_port];
	tx_offloads = txp->dev_conf.txmode.offloads;
	vlan_tci = txp->tx_vlan_id;
	vlan_tci_outer = txp->tx_vlan_id_outer;
	if (tx_offloads	& RTE_ETH_TX_OFFLOAD_VLAN_INSERT)
		ol_flags = RTE_MBUF_F_TX_VLAN;
	if (tx_offloads & RTE_ETH_TX_OFFLOAD_QINQ_INSERT)
		ol_flags |= RTE_MBUF_F_TX_QINQ;
	if (tx_offloads & RTE_ETH_TX_OFFLOAD_MACSEC_INSERT)
		ol_flags |= RTE_MBUF_F_TX_MACSEC;

	/*
	 * Initialize Ethernet header.
	 */
	rte_ether_addr_copy(&peer_eth_addrs[fs->peer_addr], &eth_hdr.dst_addr);
	rte_ether_addr_copy(&ports[fs->tx_port].eth_addr, &eth_hdr.src_addr);
	eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	if (rte_mempool_get_bulk(mbp, (void **)pkts_burst,
				nb_pkt_per_burst) == 0) {
		for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
			if (unlikely(!pkt_burst_prepare(pkts_burst[nb_pkt], mbp,
							&eth_hdr, vlan_tci,
							vlan_tci_outer,
							ol_flags,
							nb_pkt, fs))) {
				rte_mempool_put_bulk(mbp,
						(void **)&pkts_burst[nb_pkt],
						nb_pkt_per_burst - nb_pkt);
				break;
			}
		}
	} else {
		for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
			pkt = rte_mbuf_raw_alloc(mbp);
			if (pkt == NULL)
				break;
			if (unlikely(!pkt_burst_prepare(pkt, mbp, &eth_hdr,
							vlan_tci,
							vlan_tci_outer,
							ol_flags,
							nb_pkt, fs))) {
				rte_pktmbuf_free(pkt);
				break;
			}
			pkts_burst[nb_pkt] = pkt;
		}
	}

	if (nb_pkt == 0)
		return;

	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_pkt);

	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_pkt) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_pkt && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_pkt - nb_tx);
		}
	}
	fs->tx_packets += nb_tx;

	if (txonly_multi_flow)
		RTE_PER_LCORE(_ip_var) -= nb_pkt - nb_tx;

	inc_tx_burst_stats(fs, nb_tx);
	if (unlikely(nb_tx < nb_pkt)) {
		if (verbose_level > 0 && fs->fwd_dropped == 0)
			printf("port %d tx_queue %d - drop "
			       "(nb_pkt:%u - nb_tx:%u)=%u packets\n",
			       fs->tx_port, fs->tx_queue,
			       (unsigned) nb_pkt, (unsigned) nb_tx,
			       (unsigned) (nb_pkt - nb_tx));
		fs->fwd_dropped += (nb_pkt - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_pkt);
	}

	get_end_cycles(fs, start_tsc);
}

static void
pkt_gtpu_burst_transmit(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_port *txp;
	struct rte_mbuf *pkt;
	struct rte_mempool *mbp;
	struct rte_ether_hdr eth_hdr;
	uint16_t nb_tx;
	uint16_t nb_pkt;
	uint16_t vlan_tci, vlan_tci_outer;
	uint32_t retry;
	uint64_t ol_flags = 0;
	uint64_t tx_offloads;
	uint64_t start_tsc = 0;

	get_start_cycles(&start_tsc);

	mbp = current_fwd_lcore()->mbp;
	txp = &ports[fs->tx_port];
	tx_offloads = txp->dev_conf.txmode.offloads;
	vlan_tci = txp->tx_vlan_id;
	vlan_tci_outer = txp->tx_vlan_id_outer;
	if (tx_offloads	& RTE_ETH_TX_OFFLOAD_VLAN_INSERT)
		ol_flags = RTE_MBUF_F_TX_VLAN;
	if (tx_offloads & RTE_ETH_TX_OFFLOAD_QINQ_INSERT)
		ol_flags |= RTE_MBUF_F_TX_QINQ;
	if (tx_offloads & RTE_ETH_TX_OFFLOAD_MACSEC_INSERT)
		ol_flags |= RTE_MBUF_F_TX_MACSEC;

	/*
	 * Initialize Ethernet header.
	 */
	rte_ether_addr_copy(&peer_eth_addrs[fs->peer_addr], &eth_hdr.dst_addr);
	rte_ether_addr_copy(&ports[fs->tx_port].eth_addr, &eth_hdr.src_addr);
	eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	if (rte_mempool_get_bulk(mbp, (void **)pkts_burst,
				nb_pkt_per_burst) == 0) {
		for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
			if (unlikely(!pkt_burst_prepare_gtpu(pkts_burst[nb_pkt], mbp,
							&eth_hdr, vlan_tci,
							vlan_tci_outer,
							ol_flags,
							nb_pkt, fs))) {
				rte_mempool_put_bulk(mbp,
						(void **)&pkts_burst[nb_pkt],
						nb_pkt_per_burst - nb_pkt);
				break;
			}
		}
	} else {
		for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
			pkt = rte_mbuf_raw_alloc(mbp);
			if (pkt == NULL)
				break;
			if (unlikely(!pkt_burst_prepare_gtpu(pkt, mbp, &eth_hdr,
							vlan_tci,
							vlan_tci_outer,
							ol_flags,
							nb_pkt, fs))) {
				rte_pktmbuf_free(pkt);
				break;
			}
			pkts_burst[nb_pkt] = pkt;
		}
	}

	if (nb_pkt == 0)
		return;

	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_pkt);

	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_pkt) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_pkt && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_pkt - nb_tx);
		}
	}
	fs->tx_packets += nb_tx;

	if (txonly_multi_flow)
		RTE_PER_LCORE(_ip_var) -= nb_pkt - nb_tx;

	inc_tx_burst_stats(fs, nb_tx);
	if (unlikely(nb_tx < nb_pkt)) {
		if (verbose_level > 0 && fs->fwd_dropped == 0)
			printf("port %d tx_queue %d - drop "
			       "(nb_pkt:%u - nb_tx:%u)=%u packets\n",
			       fs->tx_port, fs->tx_queue,
			       (unsigned) nb_pkt, (unsigned) nb_tx,
			       (unsigned) (nb_pkt - nb_tx));
		fs->fwd_dropped += (nb_pkt - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_pkt);
	}

	get_end_cycles(fs, start_tsc);
}

// Initialize the Eth + IP + UDP + GTPU + Ext + PDU Sess.Cntr + IP + UDP
static int
tx_only_gtpu_begin(portid_t pi)
{
	uint16_t pkt_hdr_len, pkt_data_len;
	int dynf;

	pkt_hdr_len = (uint16_t)(sizeof(struct pkt_ul_hdr));
	pkt_data_len = tx_pkt_length - pkt_hdr_len;
	printf("Muthu: TxLen: %d HdrLen: %d\n", tx_pkt_length, pkt_hdr_len);

	if ((tx_pkt_split == TX_PKT_SPLIT_RND || txonly_multi_flow) &&
	    tx_pkt_seg_lengths[0] < pkt_hdr_len) {
		TESTPMD_LOG(ERR,
			    "Random segment number or multiple flow is enabled, "
			    "but tx_pkt_seg_lengths[0] %u < %u (needed)\n",
			    tx_pkt_seg_lengths[0], pkt_hdr_len);
		return -EINVAL;
	}

	setup_pkt_gtpu_headers(pkt_data_len);

	timestamp_enable = false;
	timestamp_mask = 0;
	timestamp_off = -1;
	RTE_PER_LCORE(timestamp_qskew) = 0;
	dynf = rte_mbuf_dynflag_lookup
				(RTE_MBUF_DYNFLAG_TX_TIMESTAMP_NAME, NULL);
	if (dynf >= 0)
		timestamp_mask = 1ULL << dynf;
	dynf = rte_mbuf_dynfield_lookup
				(RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, NULL);
	if (dynf >= 0)
		timestamp_off = dynf;
	timestamp_enable = tx_pkt_times_inter &&
			   timestamp_mask &&
			   timestamp_off >= 0 &&
			   !rte_eth_read_clock(pi, &timestamp_initial[pi]);

	if (timestamp_enable) {
		pkt_hdr_len += sizeof(struct tx_timestamp);

		if (tx_pkt_split == TX_PKT_SPLIT_RND) {
			if (tx_pkt_seg_lengths[0] < pkt_hdr_len) {
				TESTPMD_LOG(ERR,
					    "Time stamp and random segment number are enabled, "
					    "but tx_pkt_seg_lengths[0] %u < %u (needed)\n",
					    tx_pkt_seg_lengths[0], pkt_hdr_len);
				return -EINVAL;
			}
		} else {
			uint16_t total = 0;
			uint8_t i;

			for (i = 0; i < tx_pkt_nb_segs; i++) {
				total += tx_pkt_seg_lengths[i];
				if (total >= pkt_hdr_len)
					break;
			}

			if (total < pkt_hdr_len) {
				TESTPMD_LOG(ERR,
					    "Not enough Tx segment space for time stamp info, "
					    "total %u < %u (needed)\n",
					    total, pkt_hdr_len);
				return -EINVAL;
			}
		}
		timestamp_init_req++;
	}

	/* Make sure all settings are visible on forwarding cores.*/
	rte_wmb();
	return 0;
}

static int
tx_only_begin(portid_t pi)
{
	uint16_t pkt_hdr_len, pkt_data_len;
	int dynf;

	pkt_hdr_len = (uint16_t)(sizeof(struct rte_ether_hdr) +
				 sizeof(struct rte_ipv4_hdr) +
				 sizeof(struct rte_udp_hdr));
	pkt_data_len = tx_pkt_length - pkt_hdr_len;

	if ((tx_pkt_split == TX_PKT_SPLIT_RND || txonly_multi_flow) &&
	    tx_pkt_seg_lengths[0] < pkt_hdr_len) {
		TESTPMD_LOG(ERR,
			    "Random segment number or multiple flow is enabled, "
			    "but tx_pkt_seg_lengths[0] %u < %u (needed)\n",
			    tx_pkt_seg_lengths[0], pkt_hdr_len);
		return -EINVAL;
	}

	setup_pkt_udp_ip_headers(&pkt_ip_hdr, &pkt_udp_hdr, pkt_data_len);

	timestamp_enable = false;
	timestamp_mask = 0;
	timestamp_off = -1;
	RTE_PER_LCORE(timestamp_qskew) = 0;
	dynf = rte_mbuf_dynflag_lookup
				(RTE_MBUF_DYNFLAG_TX_TIMESTAMP_NAME, NULL);
	if (dynf >= 0)
		timestamp_mask = 1ULL << dynf;
	dynf = rte_mbuf_dynfield_lookup
				(RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, NULL);
	if (dynf >= 0)
		timestamp_off = dynf;
	timestamp_enable = tx_pkt_times_inter &&
			   timestamp_mask &&
			   timestamp_off >= 0 &&
			   !rte_eth_read_clock(pi, &timestamp_initial[pi]);

	if (timestamp_enable) {
		pkt_hdr_len += sizeof(struct tx_timestamp);

		if (tx_pkt_split == TX_PKT_SPLIT_RND) {
			if (tx_pkt_seg_lengths[0] < pkt_hdr_len) {
				TESTPMD_LOG(ERR,
					    "Time stamp and random segment number are enabled, "
					    "but tx_pkt_seg_lengths[0] %u < %u (needed)\n",
					    tx_pkt_seg_lengths[0], pkt_hdr_len);
				return -EINVAL;
			}
		} else {
			uint16_t total = 0;
			uint8_t i;

			for (i = 0; i < tx_pkt_nb_segs; i++) {
				total += tx_pkt_seg_lengths[i];
				if (total >= pkt_hdr_len)
					break;
			}

			if (total < pkt_hdr_len) {
				TESTPMD_LOG(ERR,
					    "Not enough Tx segment space for time stamp info, "
					    "total %u < %u (needed)\n",
					    total, pkt_hdr_len);
				return -EINVAL;
			}
		}
		timestamp_init_req++;
	}

	/* Make sure all settings are visible on forwarding cores.*/
	rte_wmb();
	return 0;
}

#if 0
struct fwd_engine tx_only_engine = {
	.fwd_mode_name  = "txonly",
	.port_fwd_begin = tx_only_begin,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_transmit,
};
#else
struct fwd_engine tx_only_engine = {
	.fwd_mode_name  = "txonly",
	.port_fwd_begin = tx_only_gtpu_begin,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_gtpu_burst_transmit,
};
#endif

