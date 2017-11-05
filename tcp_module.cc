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
#include "tcpstate.h"
#include "tcp.h"
#include "ip.h"

using namespace std;

#define WORD_SIZE 4

enum TYPE {
	SYN, SYNACK, ACK, PSHACK,
	FIN, FINACK, RESET
};

void handle_packet(MinetHandle &mux, MinetHandle &sock, ConnectionList<TCPState> &clist);
void make_packet(Packet &p, ConnectionToStateMapping<TCPState> &CTSM, TYPE HeaderType, int size, bool timedOut);
void handle_sock(MinetHandle &mux, MinetHandle &sock, ConnectionList<TCPState> &clist);
int send_data(const MinetHandle &mux, ConnectionToStateMapping<TCPState> &CTSM, Buffer data, bool isTimeout);

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
				handle_packet(mux, sock, clist);
		    }

		    if (event.handle == sock) {
				// socket request or response has arrived
				handle_sock(mux, sock, clist);
		    }
		}

		if (event.eventtype == MinetEvent::Timeout) {
		    // timeout ! probably need to resend some packets
		}

    }

    MinetDeinit();

    return 0;
}

void handle_packet(MinetHandle &mux, MinetHandle &sock, ConnectionList<TCPState> &clist) {

	printf("IP Address Arrival: %s", mux);

	Packet p;
	unsigned short content_len;
	unsigned char TCPHeadLen;
	unsigned char IPHeadLen;
	unsigned int curr_state;
	unsigned char flags;
	unsigned int ackNum;
	unsigned int seqNum;
	unsigned short winSize;
	unsigned short urgent;

	MinetReceive(mux,p);
	p.ExtractHeaderFromPayload<TCPHeader>(TCPHeader::EstimateTCPHeaderLength(p));
	TCPHeader tcpHead = p.FindHeader(Headers::TCPHeader);
	IPHeader ipHead = p.FindHeader(Headers::IPHeader);

	if(!tcpHead.IsCorrectChecksum(p)){
		printf("CHECKSUM ERROR!");
		return;
	}

	Connection c;
	ipHead.GetDestIP(c.src);
	ipHead.GetSourceIP(c.dest);
	ipHead.GetProtocol(c.protocol);
	tcpHead.GetDestPort(c.srcport);
	tcpHead.GetSourcePort(c.destport);

	ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

	if (cs != clist.end()) {
	  printf("HERE!!!!!!!!!!!!!!!!!!!!");
	  tcpHead.GetHeaderLen(TCPHeadLen);
	  ipHead.GetHeaderLength(IPHeadLen);
	  ipHead.GetTotalLength(content_len);
	  content_len -= WORD_SIZE * (TCPHeadLen + IPHeadLen);

	  Buffer data = p.GetPayload().ExtractFront(content_len);
	  SockRequestResponse write(WRITE,
			    (*cs).connection,
			    data,
			    content_len,
			    EOK);

		for (int i = 0; i < content_len; i++){
		  putc(isprint(data[i]) ? data[i] : '.' , stdout);
		}

		curr_state = cs->state.GetState();
	} else {
		std::cout << "Connection is not in the ConnectionList.\n";
	}

	//Get information from packet via headers
	tcpHead.GetFlags(flags);
	tcpHead.GetAckNum(ackNum);
	tcpHead.GetSeqNum(seqNum);
	tcpHead.GetWinSize(winSize);
	tcpHead.GetUrgentPtr(urgent);

	Packet p_send;
	//printf("SWITCH STATEMENT BLOCKED!!!!!!!!!!!!!!!!!!!!");
	//switch(curr_state){
		//case LISTEN:
			if(IS_SYN(flags)){
				printf("SYN RECIEVED!!!!!!!!!!!!!!!!!!!!");
				cs->connection = c;
				cs->state.SetState(SYN_RCVD);
				cs->state.last_acked = cs->state.last_sent;
				cs->state.SetLastRecvd(seqNum + 1);

				// Set timeout and send SYNACK
				cs->bTmrActive = true;
				cs->timeout=Time() + 8;
				cs->state.last_sent = cs->state.last_sent + 1;
				make_packet(p_send, *cs, SYNACK, 0, false);
				MinetSend(mux, p_send);
			}
			//break;
		//case SYN_RCVD:
			if(IS_ACK(flags)){
				printf("3 Way Handshake Complete!");  // temporary test 
				cs->state.SetState(ESTABLISHED);
				cs->state.SetLastAcked(ackNum);
				cs->state.SetSendRwnd(winSize);
				cs->state.last_sent = cs->state.last_sent + 1;

				// timeout (set for out SYNACK) is turned off because we got an ACK
				cs->bTmrActive = false;

				// Tell the other modules that the connection was created
				static SockRequestResponse * write = NULL;
				write = new SockRequestResponse(WRITE, cs->connection, 
				                                content, 0, EOK);
				MinetSend(sock, *write);
				delete write;
			}
        	//break;
        //case SYN_SENT:
	        if( (IS_SYN(flags) && IS_ACK(flags)) ){
				cs->state.SetSendRwnd(winSize);
				cs->state.SetLastRecvd(seqNum + 1);
				cs->state.last_acked = ackNum;

				cs->state.last_sent = cs->state.last_sent + 1;
				make_packet(p_send, *cs, ACK, 0, false);
				MinetSend(mux, p_send);
				cs->state.SetState(ESTABLISHED);

				cs->bTmrActive = false;
				SockRequestResponse write (WRITE, cs->connection, content, 0, EOK);
				MinetSend(sock, write);

	        }
			//break;
		//case ESTABLISHED:
			if (IS_FIN(flag)) {
				cs->state.SetState(CLOSE_WAIT);
				cs->state.SetLastRecvd(seqNum + 1);

				cs->bTmrActive = true;
				cs->timeout=Time() + 8;        

				make_packet(p_send, *cs, ACK, 0, false);
				MinetSend(mux, p_send);

				Packet p;
				cs->state.SetState(LAST_ACK);
				make_packet(p, *cs, FIN, 0, false); 
				MinetSend(mux, p);
			}

			if (IS_PSH(flag) || content_size != 0) {
				cs->state.SetSendRwnd(window_size);
				cs->state.last_recvd = seqnum + content.GetSize();

				cs->state.RecvBuffer.AddBack(content);
				SockRequestResponse write(WRITE, cs->connection,
				                           cs->state.RecvBuffer, 
				                           cs->state.RecvBuffer.GetSize(), 
				                           EOK);
				MinetSend(sock, write);

				cs->state.RecvBuffer.Clear();

				make_packet(p_send, *cs, ACK, 0, false);
				MinetSend(mux, p_send);
			}
			if (IS_ACK(flag)) {
				if (ackNum >= cs->state.last_acked) {
				  int data_acked = ack - cs->state.last_acked;
				  cs->state.last_acked = ackNum;
				  cs->state.SendBuffer.Erase(0, data_acked);

				  cs->bTmrActive = false; 
				}
				if (cs->state.GetState() == LAST_ACK) {
				  cs->state.SetState(CLOSED);
				  clist.erase(cs); 
				}
			}
			//break;
		//case LAST_ACK:
			if (IS_ACK(flags)) {
				cs->state.SetState(CLOSED);
				clist.erase(cs);
			}
			//break;
			
		//case FIN_WAIT1:
			if (IS_ACK(flags)) {
				cs->state.SetState(FIN_WAIT2);
			}
			if (IS_FIN(flags)) {
				cs->state.SetState(TIME_WAIT);
				cs->state.SetLastRecvd(seqNum + 1);
				make_packet(p_send, *cs, ACK, 0, false);

				cs->bTmrActive = true;
				cs->timeout = Time() + (2 * MSL_TIME_SECS);
				MinetSend(mux, p_send);
			}
			//break;
		
		//case FIN_WAIT2:
			if (IS_FIN(flags)) {
				cs->state.SetState(TIME_WAIT);
				cs->state.SetLastRecvd(seqNum + 1);
				make_packet(p_send, *cs, ACK, 0 ,false);

				cs->bTmrActive = true;
				cs->timeout = Time() + (2*MSL_TIME_SECS);
				MinetSend(mux, p_send); 
			}
			//break;

		//case TIME_WAIT:
			if (IS_FIN(flags)) {
				cs->state.SetLastRecvd(seqNum + 1);

				cs->timeout = Time() + 5;
				make_packet(p_send, *cs, ACK, 0 ,false);
				MinetSend(mux, p_send); 
			}
			//break;
	//}

	std::cout << ipHead << "\n";	
	std::cout << tcpHead << "\n";

}

void make_packet(Packet &p, ConnectionToStateMapping<TCPState> &CTSM, TYPE HeaderType, int size, bool timedOut){

	IPHeader ipHead;
	TCPHeader tcpHead;
	unsigned char flags = 0;
	size += TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;

	ipHead.SetSourceIP(CTSM.connection.src);
	ipHead.SetDestIP(CTSM.connection.dest);
	ipHead.SetTotalLength(size);
	ipHead.SetProtocol(IP_PROTO_TCP);
	p.PushFrontHeader(ipHead);

	tcpHead.SetSourcePort(CTSM.connection.srcport, p);
	tcpHead.SetDestPort(CTSM.connection.destport, p);
	tcpHead.SetHeaderLen(5, p);
	tcpHead.SetAckNum(CTSM.state.GetLastRecvd(), p);
	tcpHead.SetWinSize(CTSM.state.GetN(), p);
	tcpHead.SetUrgentPtr(0, p);

	switch (HeaderType) {
		case SYN:
		  SET_SYN(flags);
		  break;

		case ACK:
		  SET_ACK(flags);
		  break;
		
		case SYNACK:
		  SET_SYN(flags);
		  SET_ACK(flags);
		  break;
		
		case PSHACK:
		  SET_PSH(flags);
		  SET_ACK(flags);
		  break;
		
		case FIN:
		  SET_FIN(flags);
		  break;
		
		case FINACK:
		  SET_FIN(flags);
		  SET_ACK(flags);
		  break;
		
		case RESET:
		  SET_RST(flags);
		  break;
		
		default:
		  break;
	}
	tcpHead.SetFlags(flags, p);

	std::cout << "\nLast Acked(): " << CTSM.state.GetLastAcked() << "\n";
	std::cout << "\nSeqNum  +  1: " << CTSM.state.GetLastSent() + 1 << "\n";

	if(timedOut){
		tcpHead.SetSeqNum(CTSM.state.GetLastAcked(), p);
	}else{
		tcpHead.SetSeqNum(CTSM.state.GetLastSent() + 1, p);
	}

	tcpHead.RecomputeChecksum(p);
	p.PushBackHeader(tcpHead);
}

void handle_sock(MinetHandle &mux, MinetHandle &sock, ConnectionList<TCPState> &clist) {
	SockRequestResponse req;
	SockRequestResponse repl;

	MinetReceive(sock, req);
	Packet p;
	ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);

	if (cs == clist.end()) {
		switch (req.type) {
			case CONNECT: {
				TCPState state(1, SYN_SENT, 5);
				ConnectionToStateMapping<TCPState> CTSM(req.connection, 
				                                      Time()+2, state, true);
				CTSM.state.last_acked = 0;
				clist.push_back(CTSM);

				make_packet(p, CTSM, SYN, 0, false);

				cs->bTmrActive = true;
				cs->timeout=Time() + 2;

				MinetSend(mux, p);

				repl.type = STATUS;
				repl.connection = req.connection;
				repl.bytes = 0;
				repl.error = EOK;
				MinetSend(sock, repl);
				break; 
			}
			 case ACCEPT: {
				TCPState state(1, LISTEN, 5);
				ConnectionToStateMapping<TCPState> CTSM(req.connection, Time(),
				                                          state, false);
				clist.push_back(CTSM);
				repl.type = STATUS;
				repl.bytes = 0;
				repl.connection = req.connection;
				repl.error = EOK;
				MinetSend(sock, repl);
				break;
			}
			case STATUS: {
				// No action needed.
				break;
			}
			case WRITE: {
				repl.type = STATUS;
				repl.connection = req.connection;
				repl.bytes = 0;
				repl.error = ENOMATCH;
				MinetSend(sock, repl);
				break;
			}
			case FORWARD: {
				// No Action needed.
				break;
			}
			 case CLOSE: {
				// Can't close a connection that doesn't exist.
				repl.type = STATUS;
				repl.connection = req.connection;
				repl.bytes = 0;
				repl.error = ENOMATCH;
				MinetSend(sock, repl);
				break;
			}
			default: {  
				break;
			}
		}
	} else {
		unsigned int state = cs->state.GetState();
		Buffer buf;
		switch (req.type) {
			case CONNECT: {
				break;
			}
			case ACCEPT: {
				break;
			}
			case WRITE: {
				if (state == ESTABLISHED) {
				  if (cs->state.SendBuffer.GetSize() + req.data.GetSize() 
				     > cs->state.TCP_BUFFER_SIZE) {
				    repl.type = STATUS;
				    repl.connection = req.connection;
				    repl.bytes = 0;
				    repl.error = EBUF_SPACE;
				    MinetSend(sock, repl);
				  } else {
					Buffer copy = req.data;
					cs->bTmrActive = true;
					cs->timeout=Time() + 8;

					int return_value = send_data(mux, *cs, copy, false);
					if (return_value == 0) {
					  repl.type = STATUS;
					  repl.connection = req.connection;
					  repl.bytes = copy.GetSize();
					  repl.error = EOK;
					  MinetSend(sock, repl);    
					}
				  }
				}
				break;   
			}
			case FORWARD: {
				break;
			}
			case CLOSE: {
				if (state == ESTABLISHED) {
				  cs->state.SetState(FIN_WAIT1);
				  cs->state.last_acked = cs->state.last_acked + 1;
				  // Start a timeout for this FIN
				  cs->bTmrActive = true;
				  cs->timeout=Time() + 8;
				  make_packet(p, *cs, FIN, 0, false);
				  MinetSend(mux, p);
				  // We tell the connection we did it.
				  repl.type = STATUS;
				  repl.connection = req.connection;
				  repl.bytes = 0;
				  repl.error = EOK;
				  MinetSend(sock, repl);
				}
				break;
			}
			case STATUS: {
				break;
			}
			default:
				break;
		}
	}
}

int send_data(const MinetHandle &mux, ConnectionToStateMapping<TCPState> &CTSM, Buffer data, bool timedOut) {
  Packet p;
  unsigned int last;
  unsigned int bytes_left;
  int count = 0;

  if (timedOut) {
  	last = 0;
    bytes_left = CTSM.state.SendBuffer.GetSize();
  } else {
    last = CTSM.state.SendBuffer.GetSize();
    CTSM.state.SendBuffer.AddBack(data);
    bytes_left = data.GetSize();
  } 

  while (bytes_left) {
    unsigned int bytes_to_send = min(bytes_left, TCP_MAXIMUM_SEGMENT_SIZE);
    char data_string[bytes_to_send + 1];

    int data_size = CTSM.state.SendBuffer.GetData(data_string, bytes_to_send, last);
    data_string[data_size + 1] = '\0';

    Buffer send_buf;
    send_buf.SetData(data_string, data_size, 0);
    cerr << "Buffer Version: \n" << send_buf;
    p = send_buf.Extract(0, data_size);
    
    if (count > 0) {
    	make_packet(p, CTSM, PSHACK, data_size, false);
    } else {
		make_packet(p, CTSM, PSHACK, data_size, timedOut);
    }

    MinetSend(mux, p);
    CTSM.state.last_sent = CTSM.state.last_sent + bytes_to_send;

    bytes_left -= bytes_to_send;
    last += data_size;
    count++;
  }

  return bytes_left;
}