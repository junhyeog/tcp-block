#include "iphdr.h"

uint16_t IpHdr::calc_checksum(IpHdr* ipHdr) {
  uint32_t res = 0;
  uint16_t* wp = (uint16_t*)ipHdr;

  //? Init checksum
  uint16_t org_checksum = ipHdr->checksum_;
  printf("org checksum: %2x %2x\n", htons(org_checksum) >> 8, htons(org_checksum) & 0xff);
  //? Clear checksum
  ipHdr->checksum_ = 0;

  //? Sum each word(2byte)
  int i = sizeof(IpHdr) >> 1;
  while (i--) res += (uint32_t)ntohs(*wp++);

  //? Fold upper 16bits
  while (res > 0xffff) res = (res >> 16) + (res & 0xffff);

  //? Restore init checksum
  ipHdr->checksum_ = org_checksum;

  //? one's complement
  uint16_t final_checksum = res;
  final_checksum = ~final_checksum;
  printf("fin checksum: %2x %2x\n", final_checksum >> 8, final_checksum & 0xff);
  return final_checksum;
}