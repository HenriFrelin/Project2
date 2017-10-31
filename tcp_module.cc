// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process



#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <sstream>
#include <iostream>

#include "Minet.h"

using namespace std;

struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()" ; 
	return os;
    }
};


int main(int argc, char * argv[]) {

    MinetHandle mux;
    MinetHandle sock;
    
    ConnectionList<TCPState> clist;

    MinetInit(MINET_TCP_MODULE);

    mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
	MinetConnect(MINET_IP_MUX) : 
	MINET_NOHANDLE;
    
    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
	MinetAccept(MINET_SOCK_MODULE) : 
	MINET_NOHANDLE;

    if ( (mux == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_IP_MUX)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));

	return -1;
    }

    if ( (sock == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));

	return -1;
    }
    
    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;

    while (MinetGetNextEvent(event, timeout) == 0) {



	if ((event.eventtype == MinetEvent::Dataflow) && 
	    (event.direction == MinetEvent::IN)) {
		
	    if (event.handle == mux) {
		// ip packet has arrived!
		printf("IP Address Arrival: %s", mux);		

		TCPHeader h;
		IPHeader i;
		Packet p;
		bool checksumok;
		unsigned short len;
		unsigned char TCPHeadLen;
		unsigned char IPHeadLen;
		unsigned short IPHLen;
		MinetReceive(mux,p);
		p.ExtractHeaderFromPayload<TCPHeader>(TCPHeader::EstimateTCPHeaderLength(p));
		h = p.FindHeader(Headers::TCPHeader);
		i = p.FindHeader(Headers::IPHeader);
		checksumok = h.IsCorrectChecksum(p);

		Connection c;
		i.GetDestIP(c.src);
		i.GetSourceIP(c.dest);
		i.GetProtocol(c.protocol);
		h.GetDestPort(c.srcport);
		h.GetSourcePort(c.destport);

		ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

		if (cs!=clist.end()) {
		  printf("HERE!!!!!!!!!!!!!!!!!!!!");
		  h.GetHeaderLen(TCPHeadLen);
		  i.GetHeaderLength(IPHeadLen);
		  len = len - (TCPHeadLen + IPHeadLen);
		  Buffer &data = p.GetPayload().ExtractFront(len);
		  SockRequestResponse write(WRITE,
				    (*cs).connection,
				    data,
				    len,
				    EOK);
			int i;
			for ( i = 0; i < len; i++ ){
			  putc( isprint(data[i]) ? data[i] : '.' , stdout );
			}		
		}

		if(!checksumok){
			printf("CHECKSUM ERROR!");	
		}
		
		std::cout << i << "\n";	
    		std::cout << h << "\n";		
	    }

	    if (event.handle == sock) {
		// socket request or response has arrived
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
	}

    }

    MinetDeinit();

    return 0;
}
