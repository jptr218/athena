#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <vector>

#include <pcap/pcap.h>
#include "packet.h" 

#include <winsock2.h>
#include <iphlpapi.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

vector<string> getDevices();
void strToIp(const char* s, uint8_t* ip);
bool spoof(pcap_t* handle, uint8_t* targetMac, uint8_t* targetIp, uint8_t* destMac, uint8_t* destIp);