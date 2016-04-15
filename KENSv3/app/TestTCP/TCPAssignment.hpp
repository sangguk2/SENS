/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();

	struct queue_node{	
		int fd;
		int addr;
		queue_node* prev;
		queue_node* next;
	};

	struct queue
	{
		int max_size;
		int current_size;
		queue_node* head;
		queue_node* tail;
	};
	
    struct socket_fd
	{
		int status;
        int fd;
        UUID syscallUUID;
        int pid;
        int domain;
        int protocol;
        socket_fd* prev;
        socket_fd* next;

		bool is_passive;
        struct sockaddr addr;

		queue* syn_queue;
		queue* established_queue;
    };
	
	struct bound_port
	{
		unsigned int num;
		bound_port* prev;
		bound_port* next;
	};
	
	virtual void enqueue(queue* q, queue_node* enter);
	virtual queue_node* dequeue(queue* q);

    virtual socket_fd* get_socket_by_fd(int fd);
    virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int protocol);
    virtual void syscall_bind(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen);
    virtual void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
    virtual void syscall_connect(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen);
    virtual void syscall_close(UUID syscallUUID, int pid, int fd);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t *addrlen);

protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
