#pragma once

#include "DNSForge.h"

void SendSpoofedPacket(PACKET_CUSTOMISATION settings);
void SendDataToPeer(PRAW_DNS_DATA rawDnsData);

PRAW_DNS_DATA ReceiveDataFromPeer();
