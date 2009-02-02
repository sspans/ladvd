/*
 * rewritten versions of some NET::CDP macro's (libcdp/src/encoding.c)
 * VOIDP_DIFF: fixed types
 * PUSH, END_TLV: use memcpy to make them strict alignment compatible
 * added support for LLDP tlv's (7/9 bits)
 * added support for EDP tlv's (0x99 marker)
 */

#define VOIDP_DIFF(P, Q) ((uintptr_t)((char *)(P) - (char *)(Q)))

typedef union {
    uint8_t uint8;
    uint16_t uint16;
    uint32_t uint32;
} tlv_t;

#define PUSH(value, type, func) \
	((length >= sizeof(type)) && \
	    ( \
		type = func(value), \
		memcpy(pos, &type, sizeof(type)), \
		length -= sizeof(type), \
		pos += sizeof(type), \
		1 \
	    ))
#define PUSH_UINT8(value) PUSH(value, type.uint8, )
#define PUSH_UINT16(value) PUSH(value, type.uint16, htons)
#define PUSH_UINT32(value) PUSH(value, type.uint32, htonl)
#define PUSH_BYTES(value, bytes) \
	((length >= (bytes)) && \
	    ( \
		memcpy(pos, value, (bytes) * sizeof(uint8_t)), \
		length -= (bytes), \
		pos += (bytes), \
		1 \
	    ))

#define START_CDP_TLV(type) \
	( \
	    tlv = pos, \
	    PUSH_UINT16(type) && PUSH_UINT16(0) \
	)
#define END_CDP_TLV \
	( \
	    type.uint16 = htons(pos - tlv), \
	    memcpy((uint16_t *)tlv + 1, &type.uint16, sizeof(uint16_t)) \
	)

#define START_LLDP_TLV(type) \
	( \
	    tlv = pos, \
	    PUSH_UINT16(type << 9) \
	)
#define END_LLDP_TLV \
	( \
	    memcpy(&type.uint16, tlv, sizeof(uint16_t)), \
	    type.uint16 |= htons((pos - (tlv + 2)) & 0x01ff), \
	    memcpy(tlv, &type.uint16, sizeof(uint16_t)) \
	)

#define EDP_TLV_MARKER   0x99
#define START_EDP_TLV(type) \
	( \
	    tlv = pos, \
	    PUSH_UINT8(EDP_TLV_MARKER) && PUSH_UINT8(type) && PUSH_UINT16(0) \
	)
#define END_EDP_TLV \
	( \
	    type.uint16 = htons(pos - tlv), \
	    memcpy((uint16_t *)tlv + 1, &type.uint16, sizeof(uint16_t)) \
	)

#define START_FDP_TLV(type) \
	( \
	    tlv = pos, \
	    PUSH_UINT16(type) && PUSH_UINT16(0) \
	)
#define END_FDP_TLV \
	( \
	    type.uint16 = htons(pos - tlv), \
	    memcpy((uint16_t *)tlv + 1, &type.uint16, sizeof(uint16_t)) \
	)

