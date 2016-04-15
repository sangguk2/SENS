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


void TCPAssignment::initialize()
{
	socket_head.prev = NULL;
	socket_head.next = &socket_tail;
	socket_tail.prev = &socket_head;
	socket_tail.next = NULL;

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
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
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
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
	for(trav = &socket_head ; trav != &socket_tail ; trav = trav->next )
	{
        if(trav->fd == fd)
            return trav;
    }
    return NULL;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int protocol)
{
	printf("syscall_socket called\n");
	socket_fd *soc = (socket_fd*)malloc(sizeof(socket_fd));
	socket_fd *trav;
	int fd1 , fd2 = 2 , inserted = 0;
	for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next )
	{
		fd1 = fd2;
		fd2 = trav->fd;
		if(fd2 < fd1 + 1)
        {
            printf("file descriptor sorting error\n");
            exit(0);
        }
		if(fd2 > fd1 + 1)
		{
            soc->fd = fd1 + 1;
            soc->next = trav;
            soc->prev = trav->prev;
            trav->prev->next = soc;
            trav->prev = soc;
            inserted = 1;
            break;
		}
    }
    if(!inserted)
    {
        soc->fd = fd2 + 1;
        soc->prev = trav->prev;
        soc->next = trav;
        soc->prev->next = soc;
        trav->prev = soc;
    }
	
	soc -> status = 0;
    soc->domain = domain;
    soc->pid = pid;
    soc->protocol = protocol;
    soc->syscallUUID = syscallUUID;
	printf("socket completed. return : %d\n\n", soc->fd);
    returnSystemCall(syscallUUID, soc->fd);
}




		

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog)
{
	
	socket_fd *f = get_socket_by_fd(fd);
	queue q;
	q->current_size =0;
	q->max_size = backlog;
	f->syn_queue = q;
	f-> status =1;;
	return 0;
	return -1;
}
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen)
{
	printf("syscall_bind called\n");
	socket_fd *f = get_socket_by_fd(fd);
	memcpy(addr, &f->addr, addrlen);
	printf("bind completed. return : 0\n");
	returnSystemCall(syscallUUID, 0);
}



	
	
void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen)
{
    returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
    socket_fd* soc = get_socket_by_fd(fd);
    socket_fd* pr = soc->prev;
    pr->next = soc->next;
    soc->next->prev = pr;

    free(soc);
    returnSystemCall(syscallUUID, 0);
}

void enqueue(queue* q, queue_node* enter){
	queue_node* trav = q->tail;
	int max = q->max_size;
	int size =  q->current_size;
	if(max<=size){
		printf("queue_size is already full\m");
		return;
	}
	if(trav == NULL){
		q->head = enter;
		q->tail = enter;
		if(size != 0){printf("queue_size is crazy0\n");};
		q->current_size = 1;
	}
	else if(trav.prev ==NULL){

		if(size != 1){

			printf("queue_size is crazy1\n");
		}
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


queue_node* dequeue(queue* q){
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

///namespace closing parenthesis
}
