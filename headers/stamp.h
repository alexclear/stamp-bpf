//go:build ignore

#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/in.h>

struct ntp_ts{
  uint32_t ntp_secs;
  uint32_t ntp_fracs;
};

// NTP CONVERSION
uint32_t timestamp(struct ntp_ts *arg) {
  uint64_t utns = bpf_ktime_get_tai_ns(); //Unix nanoseconds
  uint64_t ntps = utns / 1000000000 ; //this needs to be 64 bit to avoid over/underflows
  uint64_t ntpf = utns % 1000000000 ;
  ntps += 2208988800 ;
  /* ntpf = ( ntpf << 32 ) ; //OLD CODE */
  /* ntpf /= 1000000000 ; */
  ntpf=ntpf*1000; // each fraction is 232 picoseconds
  ntpf=ntpf/232;
  arg->ntp_secs=bpf_htonl((uint32_t) ntps); 
  arg->ntp_fracs=bpf_htonl((uint32_t) ntpf);
  return 0;
}
uint64_t untimestamp(struct ntp_ts *arg){
  uint64_t unix_s = (uint64_t) bpf_ntohl(arg->ntp_secs);
  uint64_t unix_ns = (uint64_t) bpf_ntohl(arg->ntp_fracs);
  //reverse conversion
  unix_s -= 2208988800 ;
  /* unix_ns *= 1000000000 ; // OLD CODE */
  /* unix_ns = unix_ns >> 32 ; */
  unix_ns =  unix_ns * 232   ;
  unix_ns=unix_ns/1000;
  //put it back into a full ns amount
  uint64_t res = unix_s*1000000000;
  res+= unix_ns;
  return res;
}

// SIMPLE STUBS FOR UNIX TIME INSTEAD OF NTP
/* uint32_t timestamp(struct ntp_ts *arg){ */
/*   uint64_t utns = bpf_ktime_get_tai_ns(); //Unix nanoseconds */
/*   uint64_t ntp_secs =  (utns / 1000000000) ; */
/*   uint64_t ntp_fracs =  (utns % 1000000000) ; */
/*   arg->ntp_secs = bpf_htonl( (uint32_t) ntp_secs) ; */
/*   arg->ntp_fracs = bpf_htonl( (uint32_t) ntp_fracs) ; */
/*   return 0; */
/* } */
/* uint64_t untimestamp(struct ntp_ts *arg){ */
/*   uint64_t utns= (uint64_t) bpf_ntohl(arg->ntp_secs)*1000000000; */
/*   utns+= (uint64_t) bpf_ntohl(arg->ntp_fracs); */
/*   return utns; */
/* } */

//for me check, DONE BEFORE ANY MODIFICATION OF THE PACKET, usage: if (!for_me(skb)) return TCX_PASS;
uint32_t for_me(struct __sk_buff *skb){
  //TCX_PASS evaluates to 0 so we can use this as a simple true-false function
  //is it an IP packet?
  if(skb->protocol!=bpf_htons(ETH_P_IP)) return TCX_PASS;
  //grab the actual packet
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;  
  //IP header
  struct iphdr *iph = data+sizeof(struct ethhdr);
  //these kinds of checks are mandated by the eBPF verifier, without them the program won't get loaded
  if (data + sizeof(struct iphdr) + sizeof(struct ethhdr) > data_end) return TCX_PASS;
  //Is it UDP?
  if (iph->protocol!=IPPROTO_UDP) return TCX_PASS;
  //UDP header
  struct udphdr *udph = data + sizeof(struct iphdr)+sizeof(struct ethhdr);
  if (data + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct ethhdr) > data_end) return TCX_PASS;
  //862 is a well-known TWAMP port
  //we'll need some communication mechanism for custom ports
  if (udph->dest!=bpf_ntohs(862) || udph->source!=bpf_ntohs(862)) return TCX_PASS;
  return 1;
}

// reflector func to send packet back
// TODO: don't forget to switch port numbers too when I implement custom ports
uint64_t pkt_turnaround(struct __sk_buff *skb){
  void* data = (void *)(long)skb->data;
  void* data_end = (void *)(long)skb->data_end;
  struct iphdr *iph = data+sizeof(struct ethhdr);
  if(data+sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return TCX_PASS;

  //Switch IP
  uint32_t src_ip=iph->saddr;
  uint32_t dest_ip=iph->daddr;
  bpf_skb_store_bytes(skb,sizeof(struct ethhdr)+offsetof(struct iphdr, saddr), &dest_ip, sizeof(dest_ip),0);
  bpf_skb_store_bytes(skb,sizeof(struct ethhdr)+offsetof(struct iphdr, daddr), &src_ip, sizeof(src_ip),0);
  
  //Switch MAC
  if(data+sizeof(struct ethhdr) > data_end)
    return TCX_PASS;
  unsigned char src_mac[6], dest_mac[6];
  bpf_skb_load_bytes(skb,offsetof(struct ethhdr, h_source),src_mac,6);
  bpf_skb_load_bytes(skb,offsetof(struct ethhdr, h_dest),dest_mac,6);
  bpf_skb_store_bytes(skb,offsetof(struct ethhdr, h_source),dest_mac,6,0);
  bpf_skb_store_bytes(skb,offsetof(struct ethhdr, h_dest),src_mac,6,0);

  return bpf_redirect(skb->ifindex,0);
}

//a simple function that adds the headers' sizeofs to a STAMP packet field's offsetof
uint32_t stampoffset(uint32_t offset){
  return sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)+offset;
}

// we won't use these directly but they're still handy for offsetof()
// session-sender packet(RFC 8762)
struct senderpkt{
  uint32_t seq; //sequence number
  uint32_t t1_s;
  uint32_t t1_f;
  uint16_t err; //error estimate(unused)
  uint8_t mbz[30]; //30 octets of MBZ
}__attribute__((packed));
// session-reflector packet(RFC 8762)
struct reflectorpkt {
  uint32_t seq; //reflector seq
  uint32_t t3_s; //timestamp
  uint32_t t3_f;
  uint16_t err;
  uint16_t mbz;
  uint32_t t2_s; //receive timestamp
  uint32_t t2_f;
  uint32_t s_seq; //sender seq
  uint32_t t1_s; //sender timestamp
  uint32_t t1_f;
  uint16_t s_err;
  uint16_t s_mbz;
  uint8_t ttl; //sender ttl
  uint8_t t_mbz[3]; 
}__attribute__((packed));
