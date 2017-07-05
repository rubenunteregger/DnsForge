#include <stdio.h>
#include <windows.h>
#include "DNS.h" 
#include "DNSStructs.h"
#include "DNSForge.h"


DNSFORGE_API PRAW_DNS_DATA CreateDnsResponse_A(unsigned char *reqHostName, unsigned short transactionId, unsigned char *resolvedHostIp)
{
  unsigned char responseBuffer[1024];
  DNS_HEADER requestHeaderData;
  PDNS_HEADER requestHeaderDataPtr;
  unsigned char *dnsHostName = NULL;
  QUESTION requestQueryData;
  PQUESTION requestQueryDataPtr = NULL;
  PDNS_HEADER responseHeaderDataPtr = NULL;
  unsigned long *resolvedIpAddrPtr = NULL;
  unsigned int offset = 0;
  R_DATA responseData;
  PR_DATA responseHeaderPtr = NULL;
  PRAW_DNS_DATA rawDnsData = (PRAW_DNS_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RAW_DNS_DATA));

  ZeroMemory(responseBuffer, sizeof(responseBuffer));
  ZeroMemory(&responseData, sizeof(responseData));

  // 1.1 DNS_HEADER
  requestHeaderDataPtr = (PDNS_HEADER)Add_DNS_HEADER(responseBuffer, &requestHeaderData, &offset);
  requestHeaderDataPtr->id = htons(transactionId);
  requestHeaderDataPtr->qr = 1; // this is a response
  requestHeaderDataPtr->ans_count = htons(1); // there is one answer

                                              // 1.2 DNS host name
  dnsHostName = Add_DnsHost(responseBuffer, reqHostName, &offset);

  // 1.3 QUESTION
  requestQueryDataPtr = Add_QUESTION(responseBuffer, &requestQueryData, &offset);


  // 2.0 RESPONSE NAME: 0xC0, offset
  unsigned char nameOffset = dnsHostName - responseBuffer;
  unsigned char namePosition[] = { 0xC0, nameOffset };
  Add_RawBytes(responseBuffer, namePosition, 2, &offset);

  // 2.1 R_DATA
  responseHeaderPtr = Add_R_DATA(responseBuffer, &responseData, &offset);

  // 2.2 IP address
  resolvedIpAddrPtr = Add_ResolvedIp(responseBuffer, resolvedHostIp, &offset);

  rawDnsData->data = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, offset);
  CopyMemory(rawDnsData->data, responseBuffer, offset);
  rawDnsData->dataLength = offset;

  return rawDnsData;
}