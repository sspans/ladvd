/*
 * $Id$
 *
 * Copyright (c) 2008, 2009
 *      Sten Spans <sten@blinkenlights.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _main_h
#define _main_h

// supported protocols
struct proto protos[] = {
  { 0, "LLDP", LLDP_MULTICAST_ADDR, {0}, 0,
    &lldp_packet, &lldp_check, &lldp_decode },
  { 0, "CDP",  CDP_MULTICAST_ADDR, LLC_ORG_CISCO, LLC_PID_CDP,
    &cdp_packet, &cdp_check, &cdp_decode },
  { 0, "EDP",  EDP_MULTICAST_ADDR, LLC_ORG_EXTREME, LLC_PID_EDP,
    &edp_packet, &edp_check, &edp_decode },
  { 0, "FDP",  FDP_MULTICAST_ADDR, LLC_ORG_FOUNDRY, LLC_PID_FDP,
    &fdp_packet, &fdp_check, &fdp_decode },
  { 0, "NDP",  NDP_MULTICAST_ADDR, LLC_ORG_NORTEL, LLC_PID_NDP_HELLO,
    &ndp_packet, &ndp_check, &ndp_decode },
  { 0, NULL, {0}, {0}, 0, NULL, NULL, NULL }
};

#endif /* _main_h */
