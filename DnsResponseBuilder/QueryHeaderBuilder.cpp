//#include "DNS.h"
//
//
//PDNS_QUERY_HDR GenerateQueryHeader(unsigned char *hostName, unsigned short transactionId)
//{
//  PDNS_QUERY_HDR dnsQuery = (PDNS_QUERY_HDR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof DNS_QUERY_HDR);
//  dnsQuery->is_query = 1;
//  dnsQuery->qry_count = 1;
//  dnsQuery->trans_id = transactionId;
//
//  return dnsQuery;
//}
