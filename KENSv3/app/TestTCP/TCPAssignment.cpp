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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
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
	
}

void TCPAssignment::timerCallback(void* payload)
{

}

TCPAssignment::socket_fd* TCPAssignment::get_socket_by_fd(int fd)
{
    socket_fd *trav;
	for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next )
	{
        if(trav->fd == fd)
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
	soc->status = 3;
	soc->prev = socket_tail.prev;
	soc->next = &socket_tail;
	soc->prev->next = soc;
	socket_tail.prev = soc;
	//printf("socket completed. return : %d\n\n", soc->fd);
	 returnSystemCall(syscallUUID, soc->fd);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog)
{
	socket_fd *f = get_socket_by_fd(fd);
	f->syn_queue.current_size = 0;
	f->syn_queue.max_size = backlog;
	f-> status = 1;
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen)
{
	//printf("syscall_bind called\n");
	socket_fd *f = get_socket_by_fd(fd);
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
	bound_port* trav;
	for(trav = port_head.next ; trav != &port_tail ; trav = trav->next)
	{
		if( (trav->port == ((sockaddr_in*)addr)->sin_port) &&
				(trav->addr == htonl(INADDR_ANY) ||
				 ((sockaddr_in*)addr)->sin_addr.s_addr == htonl(INADDR_ANY) || 
				 trav->addr == ((sockaddr_in*)addr)->sin_addr.s_addr) )
		{
			printf("bind : port overlapped\n");
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}

	f->is_passive = true;
	memcpy(&f->addr, addr, addrlen);

	bound_port* p = (bound_port*)malloc(sizeof(bound_port));
	p->port = ((sockaddr_in*)addr)->sin_port;
	p->addr = ((sockaddr_in*)addr)->sin_addr.s_addr;
	p->prev = port_tail.prev;
	p->next = &port_tail;
	p->prev->next = p;
	port_tail.prev = p;
	//printf("bind completed. return : 0\n");
	returnSystemCall(syscallUUID, 0);
}



	
	
void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen)
{
    
	
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
	//printf("syscall_close called\n");
	    socket_fd* soc = get_socket_by_fd(fd);
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
		if(trav->port == ((sockaddr_in*)&soc->addr)->sin_port &&
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
	socket_fd* soc = get_socket_by_fd(fd);
	if(!soc)
	{
		printf("getsockname : invalid fd\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}

	memcpy(addr, &soc->addr, *addrlen);
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


void TCPAssignment::writePacket(uint32_t *src_ip, uint32_t *dst_ip, uint16_t *src_port, uint16_t *dst_port, uint32_t *seq_num, uint32_t *ack_num, uint8_t *head_len, uint8_t *flag, uint16_t *window_size, uint16_t *urg_ptr, uint8_t *payload = NULL, size_t size = 0)
{
	Packet* p = this->allocatePacket(54+size);
	p->writeData(14+12, src_ip, 4);
	p->writeData(14+16, dst_ip, 4);
	p->writeData(14+20, src_port,2);
	p->writeData(14+20+2, dst_port,2);
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
	uint16_t csum = ~(NetworkUtil::tcp_sum(*src_ip, *dst_ip, forsum, 20+size));
	csum = htons(csum);
	p->writeData(14+20+16, &csum, 2);
	
	this->sendPacket("IPv4", p);
}

//namespace E closing parenthesis
}
