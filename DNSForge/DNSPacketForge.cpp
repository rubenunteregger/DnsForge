#include <windows.h>
#include "DNSStructs.h"
#include "Helper.h"


unsigned char *Add_DNS_HEADER(unsigned char *dataBuffer, PDNS_HEADER header, unsigned int *offset)
{
  unsigned char * dnsHeaderPtr = NULL;

  header->id = htons((unsigned short)GetCurrentProcessId());
  header->qr = DNS_REQUEST;
  header->opcode = 0;
  header->aa = 0;
  header->tc = 0;
  header->rd = 1;
  header->ra = 0;
  header->z = 0;
  header->ad = 0;
  header->cd = 0;
  header->rcode = 0;
  header->q_count = htons(1);
  header->ans_count = 0;
  header->auth_count = 0;
  header->add_count = 0;

  RtlCopyMemory(dataBuffer + *offset, header, sizeof(*header));
  dnsHeaderPtr = dataBuffer + *offset;
  *offset += sizeof(*header);

  return dnsHeaderPtr;
}


unsigned char *Add_DnsHost(unsigned char *dataBuffer, unsigned char *hostName, unsigned int *offset)
{
  unsigned char *dnsHostPtr = NULL;
  unsigned char dnsHostName[128];
  unsigned char tmpHostName[128];

  // Convert ASCII host name to DNS host name
  ZeroMemory(dnsHostName, sizeof(dnsHostName));
  ZeroMemory(tmpHostName, sizeof(tmpHostName));

  strncpy((char *)tmpHostName, (char *)hostName, sizeof(tmpHostName) - 1);

  ChangeToDnsNameFormat(dnsHostName, tmpHostName);

  // Copy DNS host name to the right position in the struct
  CopyMemory((char *)(dataBuffer + *offset), (char *)dnsHostName, strlen((char *)tmpHostName) + 1);
  dnsHostPtr = dataBuffer + *offset;
  *offset += strlen((char *)tmpHostName) + 1;

  return dnsHostPtr;
}


unsigned long *Add_ResolvedIp(unsigned char *dataBuffer, unsigned char *resolvedIpAddr, unsigned int *offset)
{
  unsigned long *resolvedIpPtr = NULL;
  unsigned long resolvedIp = inet_addr((char *)resolvedIpAddr);

  //  resolvedIp = htonl(resolvedIp);
  CopyMemory(dataBuffer + *offset, &resolvedIp, sizeof(resolvedIp));

  resolvedIpPtr = (unsigned long *)(dataBuffer + *offset);
  *offset += sizeof(resolvedIp);

  return resolvedIpPtr;
}


PQUESTION Add_QUESTION(unsigned char *dataBuffer, PQUESTION question, unsigned int *offset)
{
  PQUESTION dnsQuestionPtr = NULL;

  question->qtype = htons(TYPE_A);
  question->qclass = htons(0x01);

  CopyMemory(dataBuffer + *offset, question, sizeof(*question));
  dnsQuestionPtr = (PQUESTION)(dataBuffer + *offset);
  *offset += sizeof(*question);

  return dnsQuestionPtr;
}


PR_DATA Add_R_DATA(unsigned char *dataBuffer, PR_DATA responseHeader, unsigned int *offset)
{
  PR_DATA responseDataPtr = NULL;

  responseHeader->ttl = htons(0x011d);
  responseHeader->type = htons(TYPE_A);
  responseHeader->_class = htons(0x01);
  responseHeader->data_len = htons(0x0004);

  CopyMemory(dataBuffer + *offset, responseHeader, sizeof(*responseHeader));
  responseDataPtr = (PR_DATA)(dataBuffer + *offset);
  *offset += sizeof(*responseHeader);

  return responseDataPtr;
}


unsigned char *Add_RawBytes(unsigned char *dataBuffer, unsigned char *newData, unsigned int dataLength, unsigned int *offset)
{
  unsigned char *rawBytesPtr = NULL;

  CopyMemory(dataBuffer + *offset, newData, dataLength);
  rawBytesPtr = dataBuffer + *offset;
  *offset += dataLength;

  return rawBytesPtr;
}


