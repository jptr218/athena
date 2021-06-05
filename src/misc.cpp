#include "athena.h"

vector<string> getDevices() {
	vector<string> o;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&d, errbuf) == -1)
	{
		MessageBoxA(NULL, "This program requires the WinPCap driver.", "Athena", NULL);
		exit(E_ABORT);
	}

	for (; d != nullptr; d = d->next) {
		o.push_back(d->name);
	}

	return o;
}

void strToIp(const char* s, uint8_t* ip) {
    char temp_c;
    uint8_t oi = 0;
    uint8_t op = 0;
    for (uint8_t i = 0; i < strlen(s); i++) {
        temp_c = s[i];
        if (temp_c == '.') {
            ip[op] = oi;
            oi = 0;
            op += 1;
        }
        else {
            oi *= 10;
            oi += temp_c - '0';
        }
    }
    ip[op] = oi;
}