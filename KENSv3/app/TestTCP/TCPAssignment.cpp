/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <limits.h>

#define WINDOW_SIZE 10000

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}



static TCPAssignment::socket_fd socket_head, socket_tail;

static TCPAssignment::bound_port port_head, port_tail;


void TCPAssignment::initialize()
{
	socket_head.prev = NULL;
	socket_head.next = &socket_tail;
	socket_tail.prev = &socket_head;
	socket_tail.next = NULL;
	connectiion_head.prev =NULL;
	connection_head.next = &connection_tail;
	connection_tail.prev = &connection_head;
	connection_tail.next = NULL;

	port_head.prev = NULL;
	port_head.next = &port_tail;
	port_tail.prev = &port_head;
	port_tail.next = NULL;
}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr), (socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr), static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	uint8_t IHL;
	packet->readData(14, &IHL, 1);
	IHL = (IHL&0xF)*4;

	//uint8_t head_len;
	//uint16_t window_size = 51200;
	//
	uint32_t src_ip, des_ip;
	packet->readData(14+12, &src_ip, 4);
	packet->readData(14+16, &des_ip, 4);
	src_ip = ntohl(src_ip);
	des_ip = ntohl(des_ip);

	uint16_t tot_len;
	packet->readData(14+2, &tot_len, 2);
	tot_len = ntohs(tot_len) - 40;
	
	uint16_t src_port, des_port;
	packet->readData(14+IHL, &src_port, 2);
	packet->readData(14+IHL+2, &des_port, 2);
	src_port = ntohs(src_port);
	des_port = ntohs(des_port);

	uint32_t seq_num, ack_num;
	packet->readData(14+IHL+4, &seq_num, 4);
	packet->readData(14+IHL+8, &ack_num, 4);
	seq_num = ntohl(seq_num);
	ack_num = ntohl(ack_num);
	
	uint8_t flag;
	packet->readData(14+IHL+13, &flag, 1);

	uint16_t window, checksum;
	packet->readData(14+IHL+14, &window, 2);
	packet->readData(14+IHL+16, &checksum, 2);
	window = ntohs(window);

	uint16_t urg_ptr = 0;
	packet->readData(14+IHL+18, &urg_ptr, 2);

	//bool URG = flag&0x20;
	bool ACK = flag&0x10;
	//bool PSH = flag&0x8;
	bool RST = flag&0x4;
	bool SYN = flag&0x2;
	bool FIN = flag&0x1;
	
	if( SYN && ACK ) // 3hand shaking client to server 
	{
		socket_fd* trav;
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
		{
			if(trav->status == 3 && trav->connect.src_ip == htonl(des_ip) && trav->connect.des_ip == htonl(src_ip) && trav->connect.src_port == htons(des_port) && trav->connect.des_port == htons(src_port) && ack_num == trav->seq + 1)
				break;
			if(){
				break;
			}
		}
		
		if(trav != &socket_tail)	//	if	maching socket exists
		{
			src_ip = htonl(src_ip);
			des_ip = htonl(des_ip);
			src_port = htons(src_port);
			des_port = htons(des_port);
			ack_num = seq_num + 1;
			ack_num = htonl(ack_num);
			seq_num = ++(trav->seq);
			seq_num = htonl(seq_num);
			uint8_t head_len = 5<<4;
			flag = 0x10;	//	ACK
			window = htons(WINDOW_SIZE);
			urg_ptr = 0;
			writePacket(&des_ip, &src_ip, &des_port, &src_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);

			trav->status = 4;
			returnSystemCall(trav->syscallUUID, 0);
		}
		else
		{
			printf("connect : receiving SYN&ACK - no maching socket\n");
			returnSystemCall(trav->syscallUUID, -1);
		}

	}
	else if( SYN ) // 3hand shaking server to client 
	{
		sock_fd* trav;
		uint32_t cur_ip; 
		uint16_t cur_port;
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
 		{
			cur_ip = ( (sockaddr_in*)addr)->sin_addr.s_addr;
			cur_port = ((sockaddr_in*)addr)->sin_port;
			if(cur_ip==des_ip && cur_port ==des_port){
				break;
			}	
		}
			
		
		if(trav != &socket_tail)
		{
			if(trav->status == 3)//simulatenous open
			{
				trav->status = 2;
				flag = 0x10;
				ack_num = seq_num+1;
				seq_num = ++(trav_seq);
				ack_num = htonl(ack_num);
				seq_num = htonl(seq_num);
				des_port = htons(des_port);
				src_port = htons(src_port);
				uint8_t head_len = 5<<4;
				window = htons(WINDOW_SIZE);
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &ack_num, &seq_num, &head_len, &flag, &window, &urg_ptr);
				return;
			}
			
			socket_fd* con_soc = create_socket(soc-> syscallUUID, soc->pid, soc-> domain, soc-> protocol);
			ack_num = seq_num + 1;
			seq_num = ++(trav->seq);
			con_soc-> seq = seq_num;
			ack_num = htonl(ack_num);
			seq_num = htonl(seq_num);
			des_port = htons(des_port);
			src_port = htons (src_port);
			uint8_t head_len = 5<<4;
			flag = 0x12;	//	ACK&SYN
			window = htons(WINDOW_SIZE);
			writePacket(&des_ip, &src_ip, &des_port, &src_port, &ack_num, &seq_num, &head_len, &flag, &window, &urg_ptr);
			con_soc->status = 2;
			//syn packet을 queue에 추가.	
			queue_node syn_node;
			syn_node->packet = packet;
			enqueue(trav->syn_queue, syn_node);
			return;
		}
	}
	else if( ACK && FIN )
	{

	}
	else if( ACK )
	{
		sock_fd* trav;
		uint32_t cur_ip; 
		uint16_t cur_port;
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
 		{
			cur_ip = ( (sockaddr_in*)addr)->sin_addr.s_addr;
			cur_port = ((sockaddr_in*)addr)->sin_port;
			if(trav->status==2 &&cur_ip==des_ip && cur_port ==des_port){
				break;
			}	


		}
		
		if(trav != &socket_tail)
		{
			uint32_t chk_num = trav->seq;
			chk_num++;
			if(chk_num==ack_num){
				printf("server checked client 3hsk\n");
				trav_status=4;
				
				connection *c = (connection*)malloc(sizeof(connection));
				c-> src_ip =src_ip;
				c-> src_port =src_port;
				c->des_ip =des_ip;
				c->des_port = des_port;
				c->is_establiished = true;
				c->prev = connection_tail.prev;
				c->next = &connection_tail;
				c->prev->next = c;
				connection_tail.prev = c;

				returnSystemCall(trav->syscallUUID, 0);
			}
			else{
				printf("Not mached in server seq and sending ack\n");
				returnSystemCall(trav->syscallUUID, -1);

			}
		}
		else
		{
			
			printf("error at ACK\n ");
			returnSystemCall(trav->syscallUUID, -1);
		}
		
		connection* c =
		


	}
	else if( FIN )
	{

	}
	else if( RST )
	{

	}

}

void TCPAssignment::timerCallback(void* payload)
{

}

TCPAssignment::socket_fd* TCPAssignment::get_socket_by_fd(int pid, int fd)
{
    socket_fd *trav;
	for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next )
	{
        if(trav->pid == pid && trav->fd == fd)
            return trav;
    }
    return NULL;
}
TCPAssignment::connection* TCPAssignment::get_connection_by_addr(int cli_pid )
{
	connection* trav;
	for(trav = connection_head.next ; trav != &connection_tail ; trav = trav->next )
	{
		if((trav->client_pid == cli_pid ))
            		return trav;
   	 }
    return NULL;

}



void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int protocol)
{
	//printf("syscall_socket called\n");
	socket_fd *soc = (socket_fd*)malloc(sizeof(socket_fd));
	soc->fd = createFileDescriptor(pid);
   	soc->domain = domain;
   	soc->pid = pid;
   	soc->protocol = protocol;
    	soc->syscallUUID = syscallUUID;
	soc->is_passive = false;
	soc->status = 0;
	soc->connect.prev = NULL;
	soc->connect.next = NULL;
	soc->seq = 1234;

	soc->prev = socket_tail.prev;
	soc->next = &socket_tail;
	soc->prev->next = soc;
	socket_tail.prev = soc;
	//printf("socket completed. return : %d\n\n", soc->fd);
	 returnSystemCall(syscallUUID, soc->fd);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog)
{
	socket_fd *f = get_socket_by_fd(pid, fd);
	f->syn_queue.current_size = 0;
	f->syn_queue.max_size = backlog;
	f->status = 1;
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen)
{
	//printf("syscall_bind called\n");
	socket_fd *f = get_socket_by_fd(pid, fd);
	if(!f)
	{
		printf("bind : invalid fd\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}
	if(f->is_passive)
	{
		printf("bind : bound already\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}
	if(f->status != 0)
	{
		printf("connect : wrong socket status\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}

	bound_port* trav;
	for(trav = port_head.next ; trav != &port_tail ; trav = trav->next)
	{
		if( (trav->port == ntohs(((sockaddr_in*)addr)->sin_port)) &&
				(trav->addr == htonl(INADDR_ANY) ||
				 ((sockaddr_in*)addr)->sin_addr.s_addr == htonl(INADDR_ANY) || 
				 trav->addr == ((sockaddr_in*)addr)->sin_addr.s_addr) )
		{
			printf("bind : port overlapped\n");
			returnSystemCall(syscallUUID, -1);
			return;
		}
		if( trav->port > ntohs(((sockaddr_in*)addr)->sin_port) )
			break;
	}

	f->is_passive = true;
	memcpy(&f->addr, addr, addrlen);

	bound_port* p = (bound_port*)malloc(sizeof(bound_port));
	p->port = ntohs(((sockaddr_in*)addr)->sin_port);
	p->addr = ((sockaddr_in*)addr)->sin_addr.s_addr;
	p->prev = trav->prev;
	p->next = trav;
	p->prev->next = p;
	trav->prev = p;
	
	//printf("bind completed. return : 0\n");
	returnSystemCall(syscallUUID, 0);
}



	
	
void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen)
{
 	socket_fd *f = get_socket_by_fd(pid, fd);
	if(!f)
	{
		printf("connect : invalid fd\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}((
	if(f->status != 0)
	{
		printf("connect : wrong socket status\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}

	uint32_t src_ip, des_ip = ((sockaddr_in*)addr)->sin_addr.s_addr;
	uint16_t src_port, des_port = ((sockaddr_in*)addr)->sin_port;

	if(!getHost()->getIPAddr((uint8_t*)&src_ip, getHost()->getRoutingTable((uint8_t*)&des_ip)))
	{
		printf("connect : get src_ip error\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}

	uint16_t min = 1024;
	bound_port* trav;
	for(trav = port_head.next ; trav != &port_tail ; trav = trav->next)
	{
		if(trav->port == min)
		{
			if(min == USHRT_MAX)
			{
				printf("connect : ports are full\n");
				returnSystemCall(syscallUUID, -1);
				return;
			}
			min++;
		}
		else if( trav->port > min)
			break;
	}

	bound_port* p = (bound_port*)malloc(sizeof(bound_port));
	p->port = min;
	p->addr = src_ip;
	p->prev = trav->prev;
	p->next = trav;
	p->prev->next = p;
	trav->prev = p;
	
	src_port = htons(src_port);
	uint32_t seq_num = ++(f->seq) , ack_num = 0;
	seq_num = htonl(seq_num);

	uint8_t head_len = 5<<4;
	uint8_t flag = 0x2;
	uint16_t window_size = htons(WINDOW_SIZE);
	uint16_t urg_ptr = 0;
	
	writePacket(&src_ip, &des_ip, &src_port, &des_port, &seq_num, &ack_num, &head_len, &flag, &window_size, &urg_ptr);

	f->status = 3;
	f->connect.src_ip = src_ip;
	f->connect.des_ip = des_ip;
	f->connect.src_port = src_port;
	f->connect.des_port = des_port;

	connection* c = (connection*)malloc(sizeof(connection));
	c->src_ip = src_ip;
	c->src_port = src_port;
	c->des_ip = des_ip;
	c->des_port = des_port;
	c->prev = connection_tail.prev;
	c->next = &connection_tail;
	c->>prev->next = c;
	connection_tail.prev = c;
	
	
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
	//printf("syscall_close called\n");
	    socket_fd* soc = get_socket_by_fd(pid, fd);
	if(!soc)
	{
		printf("invalid fd\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}

	removeFileDescriptor(pid, fd);

	bound_port* trav;
	for(trav = port_head.next ; trav != &port_tail ; trav = trav->next)
	{
		if(trav->port == ntohs(((sockaddr_in*)&soc->addr)->sin_port) &&
				trav->addr == ((sockaddr_in*)&soc->addr)->sin_addr.s_addr)
		{
			bound_port* pr = trav->prev;
			pr->next = trav->next;
			pr->next->prev = pr;
			free(trav);
			break;
		}
	}

    socket_fd* pr = soc->prev;
    pr->next = soc->next;
    soc->next->prev = pr;
    free(soc);
//	printf("syscall_close returned 0\n");
    returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t *addrlen)
{
	socket_fd* soc = get_socket_by_fd(pid, fd);
	if(!soc)
	{
		printf("getsockname : invalid fd\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}

	memcpy(addr, &soc->addr, *addrlen);
			Packet* sendingPacket = 
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::enqueue(queue* q, queue_node* enter){
	queue_node* trav = q->tail;
	int max = q->max_size;
	int size =  q->current_size;
	if(max<=size){
		printf("queue_size is already full\n");
		return;
	}
	if(trav == NULL)
	{
		q->head = enter;
		q->tail = enter;
		if(size != 0){printf("queue_size is crazy0\n");};
		q->current_size = 1;
	}
	else if(trav->prev == NULL )
	{
		if(size != 1)
			printf("queue_size is crazy1\n");
		q->head = trav;
		q->tail = enter;
		trav->next = q->tail;
		q->tail->prev = trav;
		q->current_size = 2;
	}
	else{
		q->tail =enter;
		trav->next = q->tail;
		q->tail->prev = trav;		
		q->current_size = size++;
	}
}

TCPAssignment::queue_node* TCPAssignment::dequeue(queue* q){
	queue_node* trav = q->head;
	int size = q->current_size;
	if(trav == NULL){
		return NULL;
	}
	else if(trav->next ==NULL)
	{

		q->tail =NULL;
		q->head =NULL;
		q->current_size = size--;
		return trav;

	}
	else{
		q-> head = trav->next;
		trav->next->prev = NULL;
		q->current_size = size++;
		return trav;

	}
}


void TCPAssignment::writePacket(uint32_t *src_ip, uint32_t *des_ip, uint16_t *src_port, uint16_t *des_port, uint32_t *seq_num, uint32_t *ack_num, uint8_t *head_len, uint8_t *flag, uint16_t *window_size, uint16_t *urg_ptr, uint8_t *payload, size_t size)
{
	Packet* p = this->allocatePacket(54+size);
	p->writeData(14+12, src_ip, 4);
	p->writeData(14+16, des_ip, 4);
	p->writeData(14+20, src_port,2);
	p->writeData(14+20+2, des_port,2);
	p->writeData(14+20+4, seq_num,4); //sequence number
	p->writeData(14+20+8, ack_num,4); //ack number
	p->writeData(14+20+18, urg_ptr,2);
	p->writeData(14+20+13, flag, 1);
	p->writeData(14+20+12, head_len, 1);
	p->writeData(14+20+14, window_size, 2);
	if(payload)
		p->writeData(14+20+20, payload, size);
	
	uint8_t* forsum = (uint8_t*)malloc(20+size);
	p->readData(14+20, forsum, 20+size);
	uint16_t csum = ~(NetworkUtil::tcp_sum(*src_ip, *des_ip, forsum, 20+size));
	csum = htons(csum);
	p->writeData(14+20+16, &csum, 2);
	
	this->sendPacket("IPv4", p);
}



//namespace E closing parenthesis
}
