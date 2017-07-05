#include <stdio.h>
#include <windows.h>

#include "DNS.h"
#include "DNSForge.h"
#include "DNSStructs.h"
#include "Helper.h"


DNSFORGE_API PRAW_DNS_DATA CreateDnsQueryPacket(unsigned char *reqHostName)
{
  unsigned char requestBuffer[1024];
  DNS_HEADER requestHeaderData;
  PDNS_HEADER requestHeaderDataPtr;
  unsigned char *dnsHostName = NULL;
  QUESTION requestQueryData;
  PQUESTION requestQueryDataPtr = NULL;
  unsigned int offset = 0;
  PRAW_DNS_DATA rawDnsData = (PRAW_DNS_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RAW_DNS_DATA));


  ZeroMemory(requestBuffer, sizeof(requestBuffer));
  ZeroMemory(&requestHeaderData, sizeof(requestHeaderData));
  ZeroMemory(&requestQueryDataPtr, sizeof(requestQueryDataPtr));

  // 1. DNS_HEADER
  requestHeaderDataPtr = (PDNS_HEADER)Add_DNS_HEADER(requestBuffer, &requestHeaderData, &offset);

  // 2. DNS host name
  dnsHostName = Add_DnsHost(requestBuffer, reqHostName, &offset);

  // 3. QUESTION
  requestQueryDataPtr = Add_QUESTION(requestBuffer, &requestQueryData, &offset);

  rawDnsData->data = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, offset);
  CopyMemory(rawDnsData->data, requestBuffer, offset);
  rawDnsData->dataLength = offset;

  return rawDnsData;
}
