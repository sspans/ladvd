
#include <arpa/inet.h>

#define VOIDP_DIFF(P, Q) ((uintptr_t)((char *)(P) - (char *)(Q)))
#define VOIDP_OFFSET(P, O) ((void *)((char *)(P) + (uintptr_t)(O)))

union {
    uint8_t uint8;
    uint16_t uint16;
    uint32_t uint32;
} types;

#define PUSH(value, type, func) \
	((length >= sizeof(type)) && \
	    ( \
		type = func(value), \
		memcpy(pos, &type, sizeof(type)), \
		length -= sizeof(type), \
		pos += sizeof(type), \
		1 \
	    ))
#define PUSH_UINT8(value) PUSH(value, types.uint8, )
#define PUSH_UINT16(value) PUSH(value, types.uint16, htons)
#define PUSH_UINT32(value) PUSH(value, types.uint32, htonl)
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
	    types.uint16 = htons(pos - tlv), \
	    memcpy((uint16_t *)tlv + 1, &types.uint16, sizeof(uint16_t)) \
	)

#define START_LLDP_TLV(type) \
	( \
	    tlv = pos, \
	    PUSH_UINT16(type << 9) \
	)
#define END_LLDP_TLV \
	( \
	    memcpy(&types.uint16, tlv, sizeof(uint16_t)), \
	    types.uint16 |= htons((pos - (tlv + 2)) & 0x01ff), \
	    memcpy(tlv, &types.uint16, sizeof(uint16_t)) \
	)

