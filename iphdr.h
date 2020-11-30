#pragma once

#include <arpa/inet.h>

#include <cstdint>

#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct IpHdr final {
  uint8_t hdr_len : 4;
  uint8_t version : 4;
  uint8_t tos;
  uint16_t total_len;
  uint16_t id;
  uint8_t ip_frag_offset : 5;
  uint8_t ip_more_fragment : 1;
  uint8_t ip_dont_fragment : 1;
  uint8_t ip_reserved_zero : 1;
  uint8_t ip_frag_offset1;
  uint8_t ip_ttl;
  uint8_t ip_protocol;
  uint16_t ip_checksum;
  Ip sip_;
  Ip dip_;

  uint8_t version() { return version; }
  uint8_t hdr_len() { return hdr_len; }
  uint8_t tos() { return tos; }
  uint16_t len() { return ntohs(total_len); }
  uint16_t id() { return ntohs(id); }
  uint8_t ttl() { return ip_ttl; }
  uint8_t protocol() { return ip_protocol; }
  uint16_t checksum() { return ntohs(ip_checksum); }

  Ip sip() { return ntohl(sip_); }
  Ip dip() { return ntohl(dip_); }

  // Protocol
  enum : uint8_t {
    Icmp = 1,    // Internet Control Message Protocol
    Igmp = 2,    // Internet Group Management Protocol
    Tcp = 6,     // Transmission Control Protocol
    Udp = 17,    // User Datagram Protocol
    Sctp = 132,  // Stream Control Transport Protocol
  };
};
#pragma pack(pop)
