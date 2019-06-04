#ifndef MEMORY_OPS_H
#define MEMORY_OPS_H

uint16_t getu16 (uint8_t * array);

uint32_t getu32 (uint8_t * array);

uint64_t getu64 (uint8_t * array);

void memset_safe(void *const pnt, unsigned char val, const u32 len);

#endif /* MEMORY_OPS_H */
