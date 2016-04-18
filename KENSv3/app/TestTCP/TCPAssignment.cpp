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
        this->syscall_accept(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr*>(param.param2_ptr), static_cast<socklen_t*>(param.param3_ptr));
        break;
    case BIND:
        this->syscall_bind(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr), (socklen_t) param.param3_int);
        break;
    case GETSOCKNAME:
        this->syscall_getsockname(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr), static_cast<socklen_t*>(param.param3_ptr));
        break;
    case GETPEERNAME:
        this->syscall_getpeername(syscallUUID, pid, param.param1_int,
              static_cast<struct sockaddr *>(param.param2_ptr),
              static_cast<socklen_t*>(param.param3_ptr));
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

	//printf("recieved ack_num : %d , recieved seq_num : %d\n", ack_num, seq_num);
    //printf("src_ip %d, src_port %d\n", src_ip, src_port);
    //printf("des_ip %d, des_port %d\n", des_ip, des_port);
	
	if( SYN && ACK ) // 3hand shaking client to server 
	{
		//printf("recieved SYN&ACK\n");
		socket_fd* trav;
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
		{
			if(trav->status == 3 && trav->connect.src_ip == htonl(des_ip) && trav->connect.des_ip == htonl(src_ip) && trav->connect.src_port == htons(des_port) && trav->connect.des_port == htons(src_port) && ack_num == trav->seq + 1)
				break;
		}
		
		if(trav != &socket_tail)	//	if	maching socket exists
		{
            if(ack_num != trav->seq + 1)
                return;
			src_ip = htonl(src_ip);
			des_ip = htonl(des_ip);
			src_port = htons(src_port);
			des_port = htons(des_port);
			ack_num = seq_num+1;
			ack_num = htonl(ack_num);
			//seq_num++;
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
			//printf("connect : receiving SYN&ACK - no matching socket\n");
			returnSystemCall(trav->syscallUUID, -1);
		}
	}
	else if( SYN ) // 3hand shaking server to client 
	{
		//printf("recieved SYN\n");
		socket_fd* trav;
		uint32_t cur_ip; 
		uint16_t cur_port;
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
 		{
			//printf(" a socket with status %d\n", trav->status);
			//printf("binded address : %d\n", ntohl(((sockaddr_in*)&trav->addr)->sin_addr.s_addr));
			//printf("binded port : %d\n", ntohs(((sockaddr_in*)&trav->addr)->sin_port));
			//printf("target address was : %d\n", des_ip);
			//printf("target port was : %d\n", des_port);
			if(trav->status != 3 && trav->status != 1)
				continue;
			cur_ip = ((sockaddr_in*)&trav->addr)->sin_addr.s_addr;
			cur_port = ((sockaddr_in*)&trav->addr)->sin_port;
			
			if(cur_port == htons(des_port) &&
					(cur_ip == 0 || cur_ip == htonl(des_ip))){
				break;
			}	
		}
			
		
		if(trav != &socket_tail)
		{
			//printf("SYN : found socket\n");
			src_ip = htonl(src_ip);
			des_ip = htonl(des_ip);
			src_port = htons(src_port);
			des_port = htons(des_port);
			
			uint8_t head_len = 5<<4;
			window = htons(WINDOW_SIZE);
			uint16_t urg_ptr = 0;
			if(trav->status == 3)//simulatenous open
			{   
                //printf("SYN : simultaneous open\n");
                ack_num++;
                //ack_num = ++(trav->seq);
			    //printf("sent ack_num : %d, ", ack_num);
			    ack_num = htonl(ack_num);
			    seq_num++;
                //printf("seq_num : %d\n", seq_num);

				trav->status = 2;
				flag = 0x10;
				seq_num = htonl(seq_num);
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &ack_num, &seq_num, &head_len, &flag, &window, &urg_ptr);
			}
			else if(trav->status == 1)	//	listening socket
			{
                if(trav->syn_queue.current_size >= trav->syn_queue.max_size){
				    //printf("SYN : syn_size is already full\n");
				    return;
			    }

                ack_num++;
			    //printf("sent ack_num : %d, ", ack_num);
			    ack_num = htonl(ack_num);
			    seq_num++;

				socket_fd* con_soc = create_socket(trav->syscallUUID, trav->pid, trav->domain, trav->protocol);
				con_soc->addr = trav->addr;
				con_soc->seq = seq_num;

				seq_num = htonl(seq_num);
				flag = 0x12;	//	ACK&SYN
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &ack_num, &seq_num, &head_len, &flag, &window, &urg_ptr);
				con_soc->status = 2;
				//syn packet을 queue에 추가.	
				//printf("queue_node malloc\n");
				queue_node* syn_node = (queue_node*)malloc(sizeof(queue_node));
				syn_node->socket = con_soc;
				syn_node->src_ip = des_ip;
				syn_node->des_ip = src_ip;
				syn_node->src_port = des_port;
				syn_node->des_port = src_port;
				con_soc->connect.src_ip = des_ip;
				con_soc->connect.des_ip = src_ip;
				con_soc->connect.src_port = des_port;
				con_soc->connect.des_port = src_port;
				
				enqueue(&trav->syn_queue, syn_node);
				//printf("reacting SYN completed\n");
			}
		}
        else
            printf("SYN : no matching socket\n");
	}
	//else if( ACK && FIN )
	else if( FIN )
	{
		//printf("recieved FIN\n");
		int context = 0;
		socket_fd* trav;
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
		{
			queue_node* c = &trav->connect;
			if(c->src_ip == htonl(des_ip) && c->des_ip == htonl(src_ip)
					&& c->src_port == htons(des_port) && c->des_port == htons(src_port))
			{
				context = 1;
				break;
			}
		}

		if(context == 1)
		{
			src_ip = htonl(src_ip);
			des_ip = htonl(des_ip);
			src_port = htons(src_port);
			des_port = htons(des_port);
			
			
			ack_num++;
			//ack_num = seq_num + 1;
			ack_num = htonl(ack_num);
			seq_num++;
			//seq_num = ++(trav->seq);
			seq_num = htonl(seq_num);
			
			flag = 0x10;	//	ACK
			uint8_t head_len = 5<<4;
			window = htons(WINDOW_SIZE);
			urg_ptr = 0;

			if(trav->status == 4)	//	ESTABLISHED
			{
				//printf("stop establishing\n");
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &ack_num, &seq_num, &head_len, &flag, &window, &urg_ptr);
				trav->status = 5;
			}
			else if(trav->status == 7)	//	FIN_WAIT_1
			{
				//printf("stop fin-wait-1\n");
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &ack_num, &seq_num, &head_len, &flag, &window, &urg_ptr);
				trav->status = 8;
			}
			else if(trav->status == 9)	//	FIN_WAIT_2
			{
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &ack_num, &seq_num, &head_len, &flag, &window, &urg_ptr);
				//trav->status = 10;
				UUID id = trav->syscallUUID;
				free_socket(trav->pid, trav->fd);
				returnSystemCall(id, 0);
			}
			else
			{
				//printf("FIN : status else case (%d)", trav->status);
				return;
			}

		}
	}

	else if( ACK )
	{
		//printf("recieved ACK\n");
		socket_fd* listen_soc;
		socket_fd* trav;
		queue* synq;
		queue_node* mov;
		int context = 0;	//	1 for Establishing
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
 		{
			if(trav->status == 1
					&& (((sockaddr_in*)&trav->addr)->sin_addr.s_addr == 0
						|| ((sockaddr_in*)&trav->addr)->sin_addr.s_addr == htonl(des_ip))
					&& ((sockaddr_in*)&trav->addr)->sin_port == htons(des_port))
			{
				synq = &trav->syn_queue;
				queue_node *t;
				socket_fd* ans;
				bool finished = false;
				for( t = synq->head.next ; t != &synq->tail ; t = t->next)
				{
					ans = t->socket;
					if(ans->connect.src_port == htons(des_port)
							&& ans->connect.des_ip == htonl(src_ip)
							&& ans->connect.des_port == htons(src_port))
					{
						if(ans->status != 2)
						{
							printf("There is a socket in syn queue whose state is not 2\n");
							return;
						}
						listen_soc = trav;
						mov = t;
						finished = true;
						context = 1;
						break;
					}
				}
				if(finished)
				{
					trav = ans;
					break;
				}
			}
		}
		
		if(context == 1)	//	Establishing
		{
			//printf("recieved ack_num = %d , sent seq_num = %d\n", ack_num, trav->seq);
			if(1){
			//if(trav->seq + 1 == ack_num){
				//printf("ACK : start establishing\n");
				trav->status = 4;
				
				queue_node* pr = mov->prev;
				pr->next = mov->next;
				pr->next->prev = pr;
				(synq->current_size)--;
                
				enqueue(&listen_soc->established_queue, mov);
                manage_accept_queue(listen_soc);
			}
			else
				printf("Recieved Ack_num != Sent Seq_num + 1\n");
			return;
		}

        //printf("finding simultaneous opening socket\n");
        //check if there is simultaneous opening socket
        for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
		{
			if((trav->connect.src_ip == 0 || trav->connect.src_ip == htonl(des_ip))
				&& trav->connect.src_port == htons(des_port)
				&& trav->connect.des_ip == htonl(src_ip)
				&& trav->connect.des_port == htons(src_port)
                && trav->status == 2){
                break;
            }
			
		}
        if(trav != &socket_tail)
        {
            //printf("ACK : start simultaneous establishing\n");
            //printf("ACK UUID is %lu\n", trav->syscallUUID);
            returnSystemCall(trav->syscallUUID, 0);
		    trav->status = 4;
        }
		
		//printf("not 3-way handshaking!\n");
		//Not 3-way handshaking from here
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
		{
			if((trav->connect.src_ip == 0 || trav->connect.src_ip == htonl(des_ip))
				&& trav->connect.src_port == htons(des_port)
				&& trav->connect.des_ip == htonl(src_ip)
				&& trav->connect.des_port == htons(src_port)){
                break;
            }
			
		}
        if(trav == &socket_tail){
            //printf("There is no socket for closing\n");
             return;
        }
		if(trav->status == 6)	//	LAST_ACK
		{
			UUID id = trav->syscallUUID;
			free_socket(trav->pid, trav->fd);
			returnSystemCall(id, 0);
			//printf("server socket closed completely\n");
		}
		else if(trav->status == 7)	//	FIN_WAIT_1
		{

		}
		else if(trav->status == 8)	//	CLOSING
		{

		}

	}
	/*else if( FIN )
	{
		
	}*/
	else if( RST )
	{
		printf("recieved RST\n");
	}
}

void TCPAssignment::timerCallback(void* payload)
{
    //Time t = this->getHost()->getSystem()->getCurrentTime();
    //addTimer(payload, t);
}

TCPAssignment::socket_fd* TCPAssignment::get_socket(int pid, int fd)
{
    socket_fd *trav;
    for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next )
    {
        if(trav->pid == pid && trav->fd == fd)
            return trav;
    }
    return NULL;
}

TCPAssignment::socket_fd* TCPAssignment::create_socket(UUID syscallUUID, int pid, int domain, int protocol)
{
	socket_fd *soc = (socket_fd*)malloc(sizeof(socket_fd));
	soc->fd = createFileDescriptor(pid);
   	soc->domain = domain;
   	soc->pid = pid;
   	soc->protocol = protocol;
    soc->syscallUUID = syscallUUID;
	soc->is_passive = false;
	soc->status = 0;

	soc->connect.src_ip = 0;
	soc->connect.des_ip = 0;
	soc->connect.src_port = 0;
	soc->connect.des_port = 0;
	soc->connect.prev = NULL;
	soc->connect.next = NULL;
	
	soc->seq = 1234;

	soc->syn_queue.head.prev = NULL;
	soc->syn_queue.head.next = &soc->syn_queue.tail;
	soc->syn_queue.tail.prev = &soc->syn_queue.head;
	soc->syn_queue.tail.next = NULL;

	soc->established_queue.head.prev = NULL;
	soc->established_queue.head.next = &soc->established_queue.tail;
	soc->established_queue.tail.prev = &soc->established_queue.head;
	soc->established_queue.tail.next = NULL;

    soc->accept_queue.head.prev = NULL;
	soc->accept_queue.head.next = &soc->accept_queue.tail;
	soc->accept_queue.tail.prev = &soc->accept_queue.head;
	soc->accept_queue.tail.next = NULL;

	soc->prev = socket_tail.prev;
	soc->next = &socket_tail;
	soc->prev->next = soc;
	socket_tail.prev = soc;

	return soc;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int protocol)
{
	socket_fd* soc = create_socket(syscallUUID, pid, domain, protocol);
	returnSystemCall(syscallUUID, soc->fd);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog)
{
	socket_fd *f = get_socket(pid, fd);
	f->syn_queue.current_size = 0;
	f->syn_queue.max_size = backlog;
	f->status = 1;
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::manage_accept_queue(socket_fd* soc)
{
    queue* eq = &soc->established_queue;
    queue* aq = &soc->accept_queue;

    if(eq->head.next == &eq->tail || aq->head.next == &aq->tail)
        return;

    queue_node* q = dequeue(eq);
    queue_node* acc_info = dequeue(aq);
	socket_fd* s = q->socket;
	free(q);

	*(acc_info->addrlen) = sizeof(sockaddr_in);
	memcpy(acc_info->addr, &s->addr, *(acc_info->addrlen));
	//printf("family was %d , INET is %d\n", ((sockaddr_in*)addr)->sin_family, AF_INET);
    returnSystemCall(acc_info->syscallUUID, s->fd);
    free(acc_info);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t *addrlen)
{
    socket_fd* soc = get_socket(pid, fd);

    queue_node* newq = (queue_node*)malloc(sizeof(queue_node));
    newq->syscallUUID = syscallUUID;
    newq->addr = addr;
    newq->addrlen = addrlen;

    enqueue(&soc->accept_queue, newq);

    manage_accept_queue(soc);
}

    

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t addrlen)
{
    //printf("syscall_bind called\n");
    socket_fd *f = get_socket(pid, fd);
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
 	socket_fd *f = get_socket(pid, fd);

	if(!f)
	{
		printf("connect : invalid fd\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}
	if(f->status != 0 && f->status != 1)
	{
		printf("connect : wrong socket status\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}
	uint32_t src_ip, des_ip = ((sockaddr_in*)addr)->sin_addr.s_addr;
	uint16_t src_port, des_port = ((sockaddr_in*)addr)->sin_port;

    if(f->is_passive)
    {
        src_ip = ((sockaddr_in*)&f->addr)->sin_addr.s_addr;
        src_port = ((sockaddr_in*)&f->addr)->sin_port;
    }
    else
    {
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
    }

    f->syscallUUID = syscallUUID;
	
	uint32_t seq_num = ++(f->seq) , ack_num = 0;
    //printf("connect : sent seq_num : %d, ack_num : 0\n", seq_num);
	seq_num = htonl(seq_num);

	uint8_t head_len = 5<<4;
	uint8_t flag = 0x2;
	uint16_t window = htons(WINDOW_SIZE);
	uint16_t urg_ptr = 0;
	
	writePacket(&src_ip, &des_ip, &src_port, &des_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);

	f->status = 3;
	f->connect.src_ip = src_ip;
	f->connect.des_ip = des_ip;
	f->connect.src_port = src_port;
	f->connect.des_port = des_port;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
	socket_fd* soc = get_socket(pid, fd);
	int S = soc->status;
	switch(S)
	{
		case 0:	//	CLOSED
			free_socket(pid, fd);
			returnSystemCall(syscallUUID, 0);
			return;
		case 1:	//	LISTEN
			free_socket(pid, fd);
			returnSystemCall(syscallUUID, 0);
			return;
		case 2:	//	SYN_RCVD
			soc->status = 7;	//	FIN_WAIT_1
			break;
		case 3:	//	SYN_SENT
			soc->status = 0;
			return;
		case 4:	//	ESTABLISHED
			soc->status = 7;	//	FIN_WAIT_1
			{
				uint32_t src_ip = soc->connect.src_ip, des_ip = soc->connect.des_ip;
				uint16_t src_port = soc->connect.src_port, des_port = soc->connect.des_port;
			
				uint32_t seq_num = ++(soc->seq), ack_num = 0;
				seq_num = htonl(seq_num);

				uint8_t head_len = 5<<4 , flag = 0x1;	//	FIN
				uint16_t window = htons(WINDOW_SIZE), urg_ptr = 0;

				writePacket(&src_ip, &des_ip, &src_port, &des_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);
			}
			break;
		case 5:	//	CLOSE_WAIT
			soc->status = 6;	//	LAST_ACK
			{
				uint32_t src_ip = soc->connect.src_ip, des_ip = soc->connect.des_ip;
				uint16_t src_port = soc->connect.src_port, des_port = soc->connect.des_port;
			
				uint32_t seq_num = ++(soc->seq), ack_num = 0;
				seq_num = htonl(seq_num);

				uint8_t head_len = 5<<4 , flag = 0x1;	//	FIN
				uint16_t window = htons(WINDOW_SIZE), urg_ptr = 0;

				writePacket(&src_ip, &des_ip, &src_port, &des_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);
			}
			break;
		default:
			returnSystemCall(syscallUUID, -1);
			return;
	}

    returnSystemCall(syscallUUID, 0);
}



void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t *addrlen)
{
	socket_fd* soc = get_socket(pid, fd);
	if(!soc)
	{
		printf("getsockname : invalid fd\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}

	memcpy(addr, &soc->addr, *addrlen);
	returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, sockaddr *addr, socklen_t *addrlen)
{
    queue_node* q = &get_socket(pid,sockfd)->connect; 
    if(!q->des_ip && !q->des_port)
    {
        returnSystemCall(syscallUUID, -1);
        return;
    }
    /*if(sizeof(sockaddr_in) > *addrlen) {
        returnSystemCall(syscallUUID, -1);
        return;
    }*/
    ((sockaddr_in*)addr)->sin_addr.s_addr = q->des_ip;
    ((sockaddr_in*)addr)->sin_family=AF_INET;
    ((sockaddr_in*)addr)->sin_port = q->des_port;
    returnSystemCall(syscallUUID, 0);
}





void TCPAssignment::enqueue(queue* q, queue_node* enter){
	/*if(q->current_size >= q->max_size){
		printf("queue_size is already full\n");
		return;
	}*/
	enter->prev = q->tail.prev;
	enter->next = &q->tail;
	enter->prev->next = enter;
	q->tail.prev = enter;

	(q->current_size)++;
}

TCPAssignment::queue_node* TCPAssignment::dequeue(queue* q){
	queue_node* ret = q->head.next;
	if(ret == &q->tail)
	{
		//printf("dequeue : empty queue\n");
		return NULL;
	}
	q->head.next = ret->next;
	ret->next->prev = &q->head;
	ret->prev = NULL;
	ret->next = NULL;
	return ret;
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
    p->writeData(14+20+12, head_len, 1);
	p->writeData(14+20+13, flag, 1);
    p->writeData(14+20+14, window_size, 2);
    p->writeData(14+20+18, urg_ptr,2);
    if(payload)
        p->writeData(14+20+20, payload, size);
    uint8_t* forsum = (uint8_t*)malloc(20+size);
    p->readData(14+20, forsum, 20+size);
    uint16_t csum = ~(NetworkUtil::tcp_sum(*src_ip, *des_ip, forsum, 20+size));
	free(forsum);
    csum = htons(csum);
    p->writeData(14+20+16, &csum, 2);
    
    this->sendPacket("IPv4", p);
}

int TCPAssignment::free_socket(int pid, int fd)
{
	socket_fd* soc = get_socket(pid, fd);
	if(!soc)
	{
		printf("free_socket : no matching socket\n");
		return -1;
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

	return 0;
}

//namespace E closing parenthesis
}
