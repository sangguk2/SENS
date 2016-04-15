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

    struct socket_fd{
        int fd;
        UUID syscallUUID;
        int pid;
        int domain;
        int protocol;
        struct sockaddr addr;
        socket_fd* prev;
        socket_fd* next;
    };
    virtual socket_fd* get_socket_by_fd(int fd);
    virtual int syscall_socket(UUID syscallUUID, int pid, int domain, int protocol);
    virtual int syscall_bind(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen);
    virtual int syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
    virtual int syscall_connect(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen);
    virtual int syscall_close(UUID syscallUUID, int pid, int fd);

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
