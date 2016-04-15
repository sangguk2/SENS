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


struct TCPAssignment::socket_fd{
	int fd;
	UUID syscallUUID;
	int pid;
	int domain;
	int protocol;
	struct sockaddr addr;
	struct TCPAssignment::socket_fd* prev;
	struct TCPAssignment::socket_fd* next;
};

struct TCPAssignment::socket_fd socket_head, socket_tail;


void TCPAssignment::initialize()
{
	socket_head.prev = NULL;
	socket_head.next = &socket_tail;
	socket_tail.prev = &socket_head;
	socket_tail.nect = NULL;

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
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
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

int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, protocol){
	socket_fd *soc = (socket_fd*)malloc(sizeof(socket_fd));
	socket_fd *trav;
	int fd1 , fd = 2 , inserted = 0;
	for(trav = socket_head ; trav != socket_tail ; trav = trav->next )
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

    soc->domain = domain;
    soc->pid = pid;
    soc->protocol = protocol;
    soc->syscallUUID = syscallUUID;

    return soc->fd;
}




//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog){

	
	struct socket_fd = get_socket_by_fd(fd);
	memcpy(addr,socket_fd->addr,addrlen);
int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen)
{
	socket_fd *f = get_socket_by_fd(fd);
	memcpy(addr, &f->addr, addrlen);
	return 0;
}


struct socket_fd* TCPAssignment::get_socket_by_fd(int fd)
{
    socket_fd *trav;
	for(trav = socket_head ; trav != socket_tail ; trav = trav->next )
	{
        if(trav->fd == fd)
            return trav;
    }
    return NULL;
}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
    socket_fd* soc = get_socket_by_fd(fd);
    socket_fd* pr = soc->prev;
    pr->next = soc->next;
    soc->next->prev = pr;

    free(soc);
    return 1;
}

///namespace closing parenthesis
}
