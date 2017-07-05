#include <stdio.h>
#include <windows.h>
#include "DNS.h" 
#include "DNSStructs.h"
#include "DNSForge.h"


DNSFORGE_API PRAW_DNS_DATA CreateDnsResponse_CNAME(unsigned char *reqHostName, unsigned short transactionId, unsigned char *canonicalHostName, unsigned char *resolvedHostIp)
{
  unsigned char responseBuffer[1024];
  DNS_HEADER requestHeaderData;
  PDNS_HEADER requestHeaderDataPtr;
  unsigned char *dnsHostName = NULL;
  unsigned char *dnsCanonicalName = NULL;
  QUESTION requestQueryData;
  PQUESTION requestQueryDataPtr = NULL;
  PDNS_HEADER responseHeaderDataPtr = NULL;
  unsigned long *resolvedIpAddrPtr = NULL;
  unsigned int offset = 0;
  R_DATA responseData;
  PR_DATA responseAHeaderPtr = NULL;
  PR_DATA responseCNAMEHeaderPtr = NULL;
  PRAW_DNS_DATA rawDnsData = (PRAW_DNS_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RAW_DNS_DATA));

  ZeroMemory(responseBuffer, sizeof(responseBuffer));
  ZeroMemory(&responseData, sizeof(responseData));

  // 1.1 DNS_HEADER
  requestHeaderDataPtr = (PDNS_HEADER)Add_DNS_HEADER(responseBuffer, &requestHeaderData, &offset);
  requestHeaderDataPtr->id = htons(transactionId);
  requestHeaderDataPtr->qr = 1; // response
  requestHeaderDataPtr->ans_count = htons(2); // Two answers. CNAME and A

                                              // 1.2 DNS host name
  dnsHostName = Add_DnsHost(responseBuffer, reqHostName, &offset);

  // 1.3 QUESTION
  requestQueryDataPtr = Add_QUESTION(responseBuffer, &requestQueryData, &offset);

  // 2.0 RESPONSE CNAME: 0xC0, offset
  unsigned char nameOffset = dnsHostName - responseBuffer;
  unsigned char namePosition[] = { 0xC0, nameOffset };
  Add_RawBytes(responseBuffer, namePosition, 2, &offset);

  // 2.1 R_DATA
  responseCNAMEHeaderPtr = Add_R_DATA(responseBuffer, &responseData, &offset);
  responseCNAMEHeaderPtr->type = htons(TYPE_CNAME);
  responseCNAMEHeaderPtr->data_len = htons((unsigned short)strlen((char *)canonicalHostName) + 2);

  // 2.2 
  dnsCanonicalName = Add_DnsHost(responseBuffer, canonicalHostName, &offset);

  // 3.0 RESPONSE A: 0xC0, offset
  unsigned char cnameOffset = dnsCanonicalName - responseBuffer;
  unsigned char cnamePosition[] = { 0xC0, cnameOffset };
  Add_RawBytes(responseBuffer, cnamePosition, 2, &offset);

  // 3.1 R_DATA
  responseAHeaderPtr = Add_R_DATA(responseBuffer, &responseData, &offset);
  responseAHeaderPtr->type = htons(TYPE_A);
  responseAHeaderPtr->data_len = htons(4);

  // 3.2 IP address
  resolvedIpAddrPtr = Add_ResolvedIp(responseBuffer, resolvedHostIp, &offset);

  rawDnsData->data = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, offset);
  CopyMemory(rawDnsData->data, responseBuffer, offset);
  rawDnsData->dataLength = offset;

  return rawDnsData;
}

