#include <stdio.h>
#include <windows.h>

#include "DNSForge.h"
#include "DNSStructs.h"
#include "Helper.h"



DNSFORGE_API void DumpDnsResponsePacket(PRAW_DNS_DATA rawDnsData, unsigned char *reqHostName)
{
  unsigned char *reader;
  PDNS_HEADER responseHeaderDataPtr = NULL;
  int stop;
  int i;
  int j;
  RES_RECORD answers[20];
  RES_RECORD auth[20];
  RES_RECORD addit[20];
  struct sockaddr_in a;

  reader = &rawDnsData->data[sizeof(DNS_HEADER) + (strlen((const char*)reqHostName) + 1) + sizeof(QUESTION)];
  responseHeaderDataPtr = (PDNS_HEADER)rawDnsData->data;

  printf("\nThe response contains : ");
  printf("\n %d Questions.", ntohs(responseHeaderDataPtr->q_count));
  printf("\n %d Answers.", ntohs(responseHeaderDataPtr->ans_count));
  printf("\n %d Authoritative Servers.", ntohs(responseHeaderDataPtr->auth_count));
  printf("\n %d Additional records.\n\n", ntohs(responseHeaderDataPtr->add_count));


  //reading answers
  stop = 0;

  for (i = 0; i < ntohs(responseHeaderDataPtr->ans_count); i++)
  {
    answers[i].name = ReadName(reader, rawDnsData->data, &stop);
    reader = reader + stop;

    answers[i].resource = (PR_DATA)reader;
    reader = reader + sizeof(R_DATA);

    if (ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
    {
      answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

      for (j = 0; j < ntohs(answers[i].resource->data_len); j++)
      {
        answers[i].rdata[j] = reader[j];
      }

      answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
      reader = reader + ntohs(answers[i].resource->data_len);
    }
    else
    {
      answers[i].rdata = ReadName(reader, rawDnsData->data, &stop);
      reader = reader + stop;
    }
  }


  //read authorities
  for (i = 0; i < ntohs(responseHeaderDataPtr->auth_count); i++)
  {
    auth[i].name = ReadName(reader, rawDnsData->data, &stop);
    reader += stop;

    auth[i].resource = (PR_DATA)reader;
    reader += sizeof(R_DATA);

    auth[i].rdata = ReadName(reader, rawDnsData->data, &stop);
    reader += stop;
  }


  //read additional
  for (i = 0; i < ntohs(responseHeaderDataPtr->add_count); i++)
  {
    addit[i].name = ReadName(reader, rawDnsData->data, &stop);
    reader += stop;

    addit[i].resource = (PR_DATA)reader;
    reader += sizeof(R_DATA);

    if (ntohs(addit[i].resource->type) == 1)
    {
      addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
      for (j = 0; j < ntohs(addit[i].resource->data_len); j++)
      {
        addit[i].rdata[j] = reader[j];
      }

      addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
      reader += ntohs(addit[i].resource->data_len);
    }
    else
    {
      addit[i].rdata = ReadName(reader, rawDnsData->data, &stop);
      reader += stop;
    }
  }


  // print answers
  for (i = 0; i < ntohs(responseHeaderDataPtr->ans_count); i++)
  {
    printf("Name : %s ", answers[i].name);

    if (ntohs(answers[i].resource->type) == TYPE_A) //IPv4 address
    {
      long *p = (long*)answers[i].rdata;
      a.sin_addr.s_addr = (*p); //working without ntohl
      printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
    }

    if (ntohs(answers[i].resource->type) == TYPE_CNAME) //Canonical name for an alias
    {
      printf("has alias name : %s", answers[i].rdata);
    }

    printf("\n");
  }

  // print authorities
  for (i = 0; i < ntohs(responseHeaderDataPtr->auth_count); i++)
  {
    printf("Name : %s ", auth[i].name);
    if (ntohs(auth[i].resource->type) == 2)
    {
      printf("has authoritative nameserver : %s", auth[i].rdata);
    }
    printf("\n");
  }

  //print additional resource records
  for (i = 0; i < ntohs(responseHeaderDataPtr->add_count); i++)
  {
    printf("Name : %s ", addit[i].name);
    if (ntohs(addit[i].resource->type) == 1)
    {
      long *p = (long *)addit[i].rdata;
      a.sin_addr.s_addr = (*p); //working without ntohl
      printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
    }

    printf("\n");
  }
}

