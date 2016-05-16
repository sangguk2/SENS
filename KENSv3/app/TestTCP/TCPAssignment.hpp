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

#include <pthread.h>

#define MSS 512
#define WINDOW_NUM 100
#define WINDOW_SIZE (MSS*WINDOW_NUM)
#define RBUF_SIZE 300000
#define SBUF_NUM 200

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	
	struct socket_fd;

	struct queue_node{	
		uint32_t src_ip, des_ip;	//	network order
		uint16_t src_port, des_port;	//	network order

		UUID syscallUUID;
		sockaddr *addr;
		socklen_t *addrlen;
 		
		struct E::TCPAssignment::socket_fd* socket;
		queue_node* prev;
		queue_node* next;
	};

	struct queue
	{
		int max_size;
		int current_size;
		queue_node head;
		queue_node tail;
	};

	struct sending
	{
		//uint8_t *payload;
		uint8_t payload[MSS];
		uint32_t size;
		uint32_t seq;	//	host order
		bool sent;
		UUID timerUUID;
		pthread_mutex_t occ_lock;	//	occupied
	};

	struct writing	//	blocked syscall_write
	{
		UUID syscallUUID;
		//struct E::TCPAssignment::socket_fd *socket;
		const void *buf;
		size_t count;
		size_t sent;
		//uint32_t seq;
		writing *prev;
		writing *next;
	};

    struct socket_fd
	{
        int fd;
        UUID syscallUUID;
        int pid;
        int domain;
        int protocol;
		struct sockaddr addr;	//	network order
        socket_fd* prev;
        socket_fd* next;
		int status;
		bool is_passive;
        
		uint8_t rwin[WINDOW_SIZE];	//	receiving window
		int rwin_start;
		uint32_t rseq[WINDOW_NUM];	//	received sequence number , host order , sorted
		uint16_t rlen[WINDOW_NUM];
		int rseq_start;
		int rseq_len;
		uint8_t rbuf[RBUF_SIZE];
		int rbuf_start;
		int rbuf_len;

		bool read_blocked;
		UUID readUUID;
		uint8_t *readbuf;
		int readlen;

		//struct sending *sbuf;
		struct sending sbuf[SBUF_NUM];
		//bool got_sbuf;
		int swin_start;	//	= sbuf_start
		int swin_num;
		int sbuf_end;
		int sbuf_loc;	//	sending location
		uint32_t rack;	//	received ACK , host order
		int dup_cnt;
		
		pthread_mutex_t send_lock;
		
		struct writing whead;
		struct writing wtail;

		E::Time sent_time;
		E::Time rtt;
		E::Time devrtt;

		//queue internal_buffer;
		queue syn_queue;
		queue established_queue;
		queue accept_queue;
        //queue received_pakcets;

		uint32_t src_ip, des_ip;	//	network order
		uint16_t src_port, des_port;	//	network order

		uint32_t seq;	//	host order
        uint32_t ack;   //	host order
    };
	
	struct bound_port
	{
		uint16_t port;	//	host order
		in_addr_t addr;
		bound_port* prev;
		bound_port* next;
	};

	struct capsule	//	time capsule
	{
		socket_fd* socket;
		int location;
	};

	virtual void enqueue(queue* q, queue_node* enter);
	virtual queue_node* dequeue(queue* q);
	virtual void manage_accept_queue(socket_fd* soc);
	
	virtual socket_fd* create_socket(UUID syscallUUID, int pid, int domain, int protocol);
    virtual socket_fd* get_socket(int pid, int fd);
	virtual int free_socket(int pid, int fd);
	inline virtual int check_four(struct socket_fd *soc, uint32_t src_ip, uint32_t des_ip, uint16_t src_port, uint16_t des_port);

	virtual int lookup_rseq(struct socket_fd *s, uint32_t seq_num);
	virtual bool write_rwin(struct socket_fd *s, uint8_t* buf, uint16_t len, uint32_t seq_num);
	virtual int move_rwin(struct socket_fd *s, int len);
	virtual bool store_rseq(struct socket_fd *s, uint32_t seq_num, uint16_t len);
	virtual void print_rseq(struct socket_fd *s);
	virtual bool store_recv(struct socket_fd *s, uint8_t* payload, uint16_t len, uint32_t seq_num);
	virtual int read_rbuf(struct socket_fd *s, uint8_t *buf, int len);
	virtual bool write_rbuf(struct socket_fd *s, uint8_t *buf, uint16_t len);
	virtual uint32_t eval_ACK(struct socket_fd *s);

	virtual bool add_sbuf(struct socket_fd* s, uint8_t *payload, uint32_t size, uint32_t seq);
	virtual bool isfull_sbuf(struct socket_fd *s);

	virtual bool is_occupied(struct sending *s);
	virtual void try_send(struct socket_fd *s);
	virtual void update_rtt(struct socket_fd *s);
	virtual void block_write(UUID syscallUUID, struct socket_fd *s, const void *buf, size_t len, size_t sent);
	virtual void unblock_write(struct socket_fd *s);
	virtual bool socket_write(UUID syscallUUID, struct socket_fd *soc, const void *buf, size_t count, size_t sent, struct writing *w);

	virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int protocol);
    virtual void syscall_bind(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen);
    virtual void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
    virtual void syscall_connect(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen);
    virtual void syscall_accept(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t *addrlen);
	virtual void syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count);
	virtual void syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count);
	virtual void syscall_close(UUID syscallUUID, int pid, int fd);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t *addrlen);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, sockaddr *addr, socklen_t *addrlen);
	
	virtual void writePacket(uint32_t *src_ip, uint32_t *dst_ip, uint16_t *src_port, uint16_t *dst_port, uint32_t *seq_num, uint32_t *ack_num, uint8_t *head_len, uint8_t *flag, uint16_t *window_size, uint16_t *urg_ptr, uint8_t *payload = NULL, size_t size = 0);

	struct socket_fd socket_head, socket_tail;
	struct bound_port port_head, port_tail;
	pthread_mutex_t fd_lock;

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();

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
