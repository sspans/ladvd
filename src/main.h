
#ifndef _main_h
#define _main_h

void master_init(struct nhead *, uint16_t netifc,
		 pid_t pid, int cmdfd, int msgfd);

// supported protocols
struct proto protos[] = {
  { 1, "LLDP", LLDP_MULTICAST_ADDR, {0}, 0,
    &lldp_packet, &lldp_check, &lldp_peer, NULL },
  { 0, "CDP",  CDP_MULTICAST_ADDR, LLC_ORG_CISCO, LLC_PID_CDP,
    &cdp_packet, &cdp_check, &cdp_peer, NULL },
  { 0, "EDP",  EDP_MULTICAST_ADDR, LLC_ORG_EXTREME, LLC_PID_EDP,
    &edp_packet, &edp_check, &edp_peer, NULL },
  { 0, "FDP",  FDP_MULTICAST_ADDR, LLC_ORG_FOUNDRY, LLC_PID_FDP,
    &fdp_packet, &fdp_check, &fdp_peer, NULL },
  { 0, "NDP",  NDP_MULTICAST_ADDR, LLC_ORG_NORTEL, LLC_PID_NDP_HELLO,
    &ndp_packet, &ndp_check, &ndp_peer, NULL },
  { 0, NULL, {0}, {0}, 0, NULL, NULL, NULL, NULL }
};

struct nhead netifs;
struct mhead mqueue;

#endif /* _main_h */
