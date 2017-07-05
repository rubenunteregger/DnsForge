#pragma once

#include "DNS.h" 

typedef struct
{
  unsigned char *data;
  unsigned int dataLength;
} RAW_DNS_DATA, *PRAW_DNS_DATA;

typedef enum
{
  DNS_QUERY = 0,
  DNS_A = 1,
  DNS_CNAME = 2
} PACKET_TYPE;


typedef struct
{
  PACKET_TYPE type;
  unsigned short transactionId;
  unsigned int ttl;
  unsigned char *hostname;
  unsigned char *canonicalHost;
  unsigned char *spoofedIpAddress;
} PACKET_CUSTOMISATION, *PPACKET_CUSTOMISATION;


unsigned char *Add_DNS_HEADER(unsigned char *dataBuffer, PDNS_HEADER header, unsigned int *offset);
PQUESTION Add_QUESTION(unsigned char *dataBuffer, PQUESTION header, unsigned int *offset);
unsigned char *Add_DnsHost(unsigned char *dataBuffer, unsigned char *realHostName, unsigned int *offset);
PR_DATA Add_R_DATA(unsigned char *dataBuffer, PR_DATA responseHeader, unsigned int *offset);
unsigned char *Add_RawBytes(unsigned char *dataBuffer, unsigned char *newData, unsigned int dataLength, unsigned int *offset);
unsigned long *Add_ResolvedIp(unsigned char *dataBuffer, unsigned char *resolvedIpAddr, unsigned int *offset);