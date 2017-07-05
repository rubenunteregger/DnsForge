#pragma once
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the DNSFORGE_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// DNSFORGE_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef DNSFORGE_EXPORTS
#define DNSFORGE_API __declspec(dllexport)
#else
#define DNSFORGE_API __declspec(dllimport)
#endif

#include "DNSStructs.h"

// 
DNSFORGE_API PRAW_DNS_DATA CreateDnsQueryPacket(unsigned char *host);
DNSFORGE_API PRAW_DNS_DATA CreateDnsResponse_A(unsigned char *reqHostName, unsigned short transactionId, unsigned char *resolvedHostIp);
DNSFORGE_API PRAW_DNS_DATA CreateDnsResponse_CNAME(unsigned char *reqHostName, unsigned short transactionId, unsigned char *cname, unsigned char *resolvedHostIp);

DNSFORGE_API void DumpDnsResponsePacket(PRAW_DNS_DATA rawDnsData, unsigned char *reqHostName);
