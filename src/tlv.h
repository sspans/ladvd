
#include <malloc.h>

#define VOIDP_DIFF(P, Q) ((ptrdiff_t)((char *)(P) - (char *)(Q)))
#define VOIDP_OFFSET(P, O) ((void *)((char *)(P) + (ptrdiff_t)(O)))


#define PUSH(value, type, func) \
	((length >= sizeof(type)) && \
		( \
			*((type*)pos) = func(value), \
			length -= sizeof(type), \
			pos += sizeof(type), \
			1 \
		))
#define PUSH_UINT8(value) PUSH(value, uint8_t, )
#define PUSH_UINT16(value) PUSH(value, uint16_t, htons)
#define PUSH_UINT32(value) PUSH(value, uint32_t, htonl)
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
		*((uint16_t *)tlv + 1) = htons(pos - tlv) \
	)

#define START_LLDP_TLV(type) \
	( \
		tlv = pos, \
		PUSH_UINT16(type << 9) \
	)
#define END_LLDP_TLV \
	( \
	*((uint16_t *)tlv) |= htons((pos - (tlv + 2)) & 0x01ff) \
	)

