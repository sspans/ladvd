
#ifndef _main_h
#define _main_h

// supported protocols
struct proto protos[] = {
  { 1, "LLDP", LLDP_MULTICAST_ADDR, &lldp_packet, {0}, 0 },
  { 0, "CDP",  CDP_MULTICAST_ADDR, &cdp_packet,
	       LLC_ORG_CISCO, LLC_PID_CDP },
  { 0, "EDP",  EDP_MULTICAST_ADDR, &edp_packet,
	       LLC_ORG_EXTREME, LLC_PID_EDP },
  { 0, "FDP",  FDP_MULTICAST_ADDR, &fdp_packet,
	       LLC_ORG_FOUNDRY, LLC_PID_FDP },
  { 0, "NDP",  NDP_MULTICAST_ADDR, &ndp_packet, 
	       LLC_ORG_NORTEL, LLC_PID_NDP_HELLO },
  { 0, NULL, {0}, NULL, {0}, 0 },
};

struct nhead netifs;
struct mhead mqueue;

#endif /* _main_h */
