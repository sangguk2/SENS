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
		uint32_t src_ip, des_ip;	//	network order
		uint16_t src_port, des_port;	//	network order
		
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
        int fd;
        UUID syscallUUID;
        int pid;
        int domain;
        int protocol;
		struct sockaddr addr;
        socket_fd* prev;
        socket_fd* next;
		
		int status;
		bool is_passive;
		
		queue syn_queue;
		queue established_queue;

		queue_node connect;	//	used in client socket
    };
	
	struct bound_port
	{
		uint16_t port;	//	host order
		in_addr_t addr;
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
	virtual void writePacket(uint32_t *src_ip, uint32_t *dst_ip, uint16_t *src_port, uint16_t *dst_port, uint32_t *seq_num, uint32_t *ack_num, uint8_t *head_len, uint8_t *flag, uint16_t *window_size, uint16_t *urg_ptr, uint8_t *payload = NULL, size_t size = 0);

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
