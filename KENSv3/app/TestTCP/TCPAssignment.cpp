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
#include <unistd.h>

#define ALPHA 0.125
#define BETA 0.25
#define K 4

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

    if(pthread_mutex_init(&fd_lock, NULL) != 0)
    {
        perror("init mutex :");
        exit(1);
    }
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
        this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
        break;
    case WRITE:
        this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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
    //printf("packet Arrived with ");
	uint8_t IHL;
	packet->readData(14, &IHL, 1);
	IHL = (IHL&0xF)*4;

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

	bool ACK = flag&0x10;
	bool RST = flag&0x4;
	bool SYN = flag&0x2;
	bool FIN = flag&0x1;

	if( SYN && ACK ) // 3hand shaking client to server 
	{
        printf("SYN && ACK\n");
		socket_fd* trav;
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
		{
			if(trav->status == 3 && check_four(trav, htonl(des_ip), htonl(src_ip), htons(des_port), htons(src_port)) && ack_num == trav->seq)
				break;
		}
		
		if(trav != &socket_tail)	//	if	maching socket exists
		{
            if(ack_num != trav->seq)
                return;
			store_rseq(trav, seq_num + 1, 0);

			src_ip = htonl(src_ip);
			des_ip = htonl(des_ip);
			src_port = htons(src_port);
			des_port = htons(des_port);
			ack_num = seq_num+1;
            trav->ack = ack_num;
            seq_num = trav->seq;
			ack_num = htonl(ack_num);
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
			returnSystemCall(trav->syscallUUID, -1);
		}
	}
	else if( SYN ) // 3hand shaking server to client 
	{
        printf("SYN\n");
		socket_fd* trav;
		uint32_t cur_ip; 
		uint16_t cur_port;
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
 		{
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
			src_ip = htonl(src_ip);
			des_ip = htonl(des_ip);
			src_port = htons(src_port);
			des_port = htons(des_port);
			
			uint8_t head_len = 5<<4;
			window = htons(WINDOW_SIZE);
			uint16_t urg_ptr = 0;
			if(trav->status == 3)//simulatenous open
			{   
                //  simultaneous open
                trav->ack = seq_num + 1;
                trav->seq = ack_num + 1;
			    seq_num = trav->seq;
                ack_num = trav->ack;
			    ack_num = htonl(ack_num);
				seq_num = htonl(seq_num);

                trav->status = 2;
				flag = 0x10;
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);
			}
			else if(trav->status == 1)	//	listening socket
			{
                if(trav->syn_queue.current_size >= trav->syn_queue.max_size){
				    return;
			    }
                trav->ack = seq_num + 1;
                trav->seq = ack_num + 1;
			    seq_num = trav->seq;
                ack_num = trav->ack;

				socket_fd* con_soc = create_socket(trav->syscallUUID, trav->pid, trav->domain, trav->protocol);
				con_soc->addr = trav->addr;
				con_soc->seq = seq_num;
                con_soc->ack = ack_num;
			    ack_num = htonl(ack_num);
				seq_num = htonl(seq_num);
				flag = 0x12;	//	ACK&SYN
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);
				con_soc->status = 2;
				queue_node* syn_node = (queue_node*)malloc(sizeof(queue_node));
				syn_node->socket = con_soc;
				syn_node->src_ip = des_ip;
				syn_node->des_ip = src_ip;
				syn_node->src_port = des_port;
				syn_node->des_port = src_port;
				con_soc->src_ip = des_ip;
				con_soc->des_ip = src_ip;
				con_soc->src_port = des_port;
				con_soc->des_port = src_port;
				
				enqueue(&trav->syn_queue, syn_node);
			}
		}
        else
            printf("SYN : no matching socket\n");
	}
	else if( FIN )
	{
        printf("FIN\n");
		int context = 0;
		socket_fd* trav;
		for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
		{
			if(check_four(trav, htonl(des_ip), htonl(src_ip), htons(des_port), htons(src_port)))
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
			
            if(seq_num == trav->ack)
                trav->ack ++;
            seq_num = trav->seq;
            ack_num = trav->ack;
			//seq_num = ack_num + 1;
            //ack_num = seq_num = 1;
            //trav->ack = ack_num;
			ack_num = htonl(ack_num);
			seq_num = htonl(seq_num);
			
			flag = 0x10;	//	ACK
			uint8_t head_len = 5<<4;
			window = htons(WINDOW_SIZE);
			urg_ptr = 0;

			if(trav->status == 4)	//	ESTABLISHED
			{
				//printf("stop establishing\n");
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);
				trav->status = 5;
			}
			else if(trav->status == 7)	//	FIN_WAIT_1
			{
				//printf("stop fin-wait-1\n");
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);
				trav->status = 8;
			}
			else if(trav->status == 9)	//	FIN_WAIT_2
			{
				writePacket(&des_ip, &src_ip, &des_port, &src_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);
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
		//printf("ACK\n");
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
					if(ans->src_port == htons(des_port)
							&& ans->des_ip == htonl(src_ip)
							&& ans->des_port == htons(src_port))
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
			if(1){
				trav->status = 4;
                trav->seq ++;
				store_rseq(trav, seq_num, 0);
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
			if((trav->src_ip == 0 || trav->src_ip == htonl(des_ip))
				&& trav->src_port == htons(des_port)
				&& trav->des_ip == htonl(src_ip)
				&& trav->des_port == htons(src_port))
                break;
		}

        if(trav == &socket_tail)
             return;

        if(trav->status == 2)   //  simultaneous open
        {
			if(tot_len == 0)
				store_rseq(trav, seq_num, 0);
		    trav->status = 4;
            trav->seq ++;
            returnSystemCall(trav->syscallUUID, 0);
			context = 2;
        }
		else if(trav->status == 4)
		{
			context = 4;
		}
        else if(trav->status == 5)  //  CLOSE_WAIT
        {
            context = 5;
        }
		else if(trav->status == 6)	//	LAST_ACK
		{
			UUID id = trav->syscallUUID;
			free_socket(trav->pid, trav->fd);
			returnSystemCall(id, 0);
            return;
			//printf("server socket closed completely\n");
		}
		else if(trav->status == 7)	//	FIN_WAIT_1
		{
			context = 7;
		}
		else if(trav->status == 8)	//	CLOSING
		{
			context = 8;
		}
		else
		{
			context = 100;
			printf("other case in ACK with status = %d\n", trav->status);
		}
        
        if(tot_len > 0)
        {
			if(seq_num >= trav->ack)
			{
            	uint8_t *payload = (uint8_t*)malloc(tot_len);
            	packet->readData(54, payload, tot_len);
            	if(store_recv(trav, payload, tot_len, seq_num))
				{
					if(trav->read_blocked)
					{
						
	                    int read = ((int)trav->rbuf_len > (int)trav->readlen) ? trav->readlen : trav->rbuf_len;
	                    trav->read_blocked = false;
						returnSystemCall(trav->readUUID, read_rbuf(trav, trav->readbuf, read));
					}
				}
                else
                    printf("cannot receive\n");
				free(payload);
			}
            src_ip = htonl(src_ip);
		    des_ip = htonl(des_ip);
		    src_port = htons(src_port);
		    des_port = htons(des_port);
		
		    seq_num = trav->seq;
            ack_num = trav->ack;
		    seq_num = htonl(seq_num);
            ack_num = htonl(ack_num);
		
		    flag = 0x10;	//	ACK
		    uint8_t head_len = 5<<4;
		    window = htons(WINDOW_SIZE);
		    urg_ptr = 0;

			writePacket(&des_ip, &src_ip, &des_port, &src_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);
        }
		if(context != 2)
		{
            struct socket_fd *s = trav;
            if(ack_num == s->rack)
            {
                if(((++(s->dup_cnt)) % 3 == 0) && (s->dup_cnt > 0))
                {
                    bool chance = isfull_sbuf(s), flag = true;
                        
                    int i;
                    for(i = s->swin_start ; ; i = (i + 1) % SBUF_NUM)
                    {
                        if(i == s->sbuf_end)
                        {
                            if(chance)
                                chance = false;
                            else
                                break;
                        }

                        struct sending *pac = &s->sbuf[i];
                        printf("3 dup loop : s->sbuf[%d]->seq = %u , duped ACK = %u\n", i, pac->seq, s->rack);
                        if(pac->seq == s->rack)
                        {
                            printf("ACK : 3 dup ack - seq found!\n");
                            s->sbuf_loc = i;
                            s->swin_num /= 2;
							if(s->swin_num > window/MSS)
								s->swin_num = window/MSS;
							if(s->swin_num == 0)
								s->swin_num ++;
                            try_send(s);
                            flag = false;
                            break;
                        }
                    }
                    if(i == s->sbuf_end && flag)
                    {
                        printf("ACK : 3 dup ack - not seq found\n");
                    }
                }
            }
            else
            {
                s->rack = ack_num;
                s->dup_cnt = 1;
            }

            uint32_t first_seq = s->sbuf[s->swin_start].seq;
		    if(ack_num < first_seq && !((ack_num < USHRT_MAX) && (first_seq > UINT_MAX - USHRT_MAX)))
            {
                printf("ACK : too small ack received, ack_num = %u, first_seq = %u, len = %u, swin_start = %d, sent = %d\n", ack_num, first_seq, s->sbuf[s->swin_start].size, s->swin_start, s->sbuf[s->swin_start].sent);
                printf("next seq = %u, %u, %u\n", s->sbuf[s->swin_start + 1].seq, s->sbuf[s->swin_start + 2].seq, s->sbuf[s->swin_start +3].seq);
                return;
            }
            printf("ACK : not small ack received, ack_num = %u, first_seq = %u, swin_start = %d\n", ack_num, first_seq, s->swin_start);
            
            bool chance = isfull_sbuf(s);
            int i, end = s->sbuf_end;
            for(i = s->swin_start ; ; i = (i + 1) % SBUF_NUM)
            {
                if(i == end)
                {
                    if(chance)
                        chance = false;
                    else
                        break;
                }
                struct sending *pac = &s->sbuf[i];
                uint32_t pred_ack, sub = UINT_MAX - pac->seq;
                if(pac->size > sub)
                    pred_ack = pac->size - sub - 1;
                else
                    pred_ack = pac->seq + pac->size;
                //printf("pred_ack = %u\n", pred_ack);
                if(((ack_num > pred_ack) && !((ack_num > UINT_MAX - USHRT_MAX) && (pred_ack < USHRT_MAX)))
                || ((ack_num < pred_ack) && ((ack_num < USHRT_MAX) && (pred_ack > UINT_MAX - USHRT_MAX)))
                || (ack_num == pred_ack))
                {
					cancelTimer(pac->timerUUID);
					update_rtt(s);
                    //printf("ack <= pred_ack case\n");
                    pthread_mutex_unlock(&s->sbuf[s->swin_start].occ_lock);
                    //printf("flag1\n");
                    s->swin_start = (s->swin_start + 1) % SBUF_NUM;
                    if(s->swin_num < 100)
                        s->swin_num ++;
					if(s->swin_num > window/MSS)
						s->swin_num = window/MSS;
					if(s->swin_num == 0)
						s->swin_num ++;
                    unblock_write(s);
                    //printf("flag2\n");
                    try_send(s);
                    //manage timer
                }
                else
                {
                    //printf("increasing swin_start loop : break with s->sbuf[%d]->seq = %u, pred_ack = %u\n", i, pac->seq, pred_ack);
                    break;
                }
            }
        }
	}
	else if( RST )
	{
		printf("recieved RST\n");
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	capsule *cap = (capsule*)payload;
	socket_fd *s = cap->socket;
	s->sbuf_loc = cap->location;
    s->swin_num /= 2;
	if(s->swin_num == 0);
    	s->swin_num ++;
    try_send(s);
}

void TCPAssignment::print_rseq(struct socket_fd *s)
{
    printf("[[print_rseq]]\n");
    int i;
    for(i = 0 ; i < s->rseq_len ; i ++)
    {
        int j = (s->rseq_start + i) % WINDOW_NUM;
        printf("rseq[%d] = %u , rlen[%d] = %u\n", i, s->rseq[j], i, s->rlen[j]);
    }
}

int TCPAssignment::lookup_rseq(struct socket_fd *s, uint32_t seq_num)
{
	int i, j;
	for(i = 0 ; i < s->rseq_len ; i ++)
	{
        j = (s->rseq_start + i) % WINDOW_NUM;
		if(s->rseq[j] == seq_num)
        {
            if(s->rlen[j] != 0)
			    return j;
            if(s->rlen[j] == 0);
                return -(j + 1);
            printf("lookup_resq : negative len found\n");
            return -WINDOW_NUM;
        }
	}
	return WINDOW_NUM;
}

bool TCPAssignment::write_rwin(struct socket_fd *s, uint8_t* buf, uint16_t len, uint32_t seq_num)
{
    int from = s->rwin_start;
    if(seq_num < USHRT_MAX && s->rseq[s->rseq_start] > UINT_MAX - USHRT_MAX)
        from += UINT_MAX - s->rseq[s->rseq_start] + 1 + seq_num;
    else
        from += seq_num - s->rseq[s->rseq_start];
    from %= WINDOW_SIZE;
	if(from + (int)len >= WINDOW_SIZE)
	{
		memcpy(s->rwin + from, buf, WINDOW_SIZE - from);
		memcpy(s->rwin, buf + WINDOW_SIZE - from, (int)len - WINDOW_SIZE + from);
	}
	else
	{
		if(from < s->rwin_start && from+(int)len >= s->rwin_start)
			return false;
		memcpy(s->rwin + from, buf, len);
	}
	return true;
}

bool TCPAssignment::store_rseq(struct socket_fd *s, uint32_t seq_num, uint16_t len)
{
    int n = lookup_rseq(s, seq_num);
	if(n < WINDOW_NUM && n >= 0)
    {
        printf("store_rseq-already_exist\n");
		return false;
    }
    //printf("store_rseq : new store with seq=%u , len=%u\n", seq_num, (uint32_t)len);
    if(s->rseq_len == 0)
    {
	    s->rseq[s->rseq_start] = seq_num;
	    s->rlen[s->rseq_start] = len;
	    s->rseq_len ++;
        return true;
    }

    int i, j, i2, j2, j3;
	for(i = 0 ; i < s->rseq_len ; i ++)
	{
        j = (s->rseq_start + i) % WINDOW_NUM;
		if(s->rseq[j] == seq_num)
        {
            if(s->rlen[j] == 0)
			{
                for(i2 = s->rseq_len - 1 ; i2 >= i + 1 ; i2 --)
                {
                    j2 = (s->rseq_start + i2) % WINDOW_NUM;
                    j3 = (j2 + 1) % WINDOW_NUM;
                    s->rseq[j3] = s->rseq[j2];
                    s->rlen[j3] = s->rlen[j2];
                }
                j2 = (j + 1) % WINDOW_NUM;
                s->rseq[j2] = seq_num;
                s->rlen[j2] = len;
                s->rseq_len ++;
            }
            return true;
        }
        if(s->rseq[j] > seq_num)
        {
            if((int)(s->rseq[j]) < (int)seq_num)
                continue;
            if(i == 0)
            {
                printf("store_rseq : surprize case\n");
                return false;
            }
            for(i2 = s->rseq_len - 1 ; i2 >= i ; i2 --)
            {
                j2 = (s->rseq_start + i2) % WINDOW_NUM;
                j3 = (j2 + 1) % WINDOW_NUM;
                s->rseq[j3] = s->rseq[j2];
                s->rlen[j3] = s->rlen[j2];
            }
            s->rseq[j] = seq_num;
            s->rlen[j] = len;
            s->rseq_len ++;
            return true;
        }
	}
    j = (s->rseq_start + s->rseq_len) % WINDOW_NUM;
    s->rseq[j] = seq_num;
	s->rlen[j] = len;
	s->rseq_len ++;
    return true;
}

bool TCPAssignment::store_recv(struct socket_fd *s, uint8_t* payload, uint16_t len, uint32_t seq_num)
{
	if(s->rseq_len == WINDOW_NUM)
    {
        printf("store_recv-rseq full\n");
		return false;
    }
    if(store_rseq(s, seq_num, len))
    {
	    if(!write_rwin(s, payload, len, seq_num))
	    {
            printf("store_recv-rwin full\n");
	        return false;
        }
    }

    if(len > 0)
    {
        eval_ACK(s);
        if(s->ack < USHRT_MAX && s->rseq[s->rseq_start] > UINT_MAX - USHRT_MAX)
            len = UINT_MAX - s->rseq[s->rseq_start] + 1 + s->ack;
        else
            len = s->ack - s->rseq[s->rseq_start];
        move_rwin(s, len);
    }
	return true;
}

int TCPAssignment::read_rbuf(struct socket_fd *s, uint8_t *buf, int len)
{
    if(s->rbuf_start + len >= RBUF_SIZE)
	{
		memcpy(buf, s->rbuf + s->rbuf_start, RBUF_SIZE - s->rbuf_start);
		memcpy(buf + RBUF_SIZE - s->rbuf_start, s->rbuf, len - RBUF_SIZE + s->rbuf_start);
		s->rbuf_start += len - RBUF_SIZE;
        s->rbuf_len -= len;
		if(s->rbuf_start < 0)
		{
			printf("read_rbuf : s->rbuf_start became negative\n");
			return -1;
		}
	}
	else
	{
		memcpy(buf, s->rbuf + s->rbuf_start, len);
		s->rbuf_start += len;
        s->rbuf_len -= len;
	}
    return len;
}

bool TCPAssignment::write_rbuf(struct socket_fd *s, uint8_t* buf, uint16_t len)
{
	int from = (s->rbuf_start + s->rbuf_len) % RBUF_SIZE;
	if(from + (int)len >= RBUF_SIZE)
	{
		if(from <= s->rbuf_start || ((int)len - RBUF_SIZE + from > s->rbuf_start))
			return false;
		memcpy(s->rbuf + from, buf, RBUF_SIZE - from);
		memcpy(s->rbuf, buf + RBUF_SIZE - from, (int)len - RBUF_SIZE + from);
	}
	else
	{
		if(from < s->rbuf_start && from+(int)len >= s->rbuf_start)
			return false;
		memcpy(s->rbuf + from, buf, len);
	}
    s->rbuf_len += len;
	return true;
}

int TCPAssignment::move_rwin(struct socket_fd *s, int len)
{
	if(s->rwin_start + len >= WINDOW_SIZE)
	{   
        write_rbuf(s, s->rwin + s->rwin_start, WINDOW_SIZE - s->rwin_start);
        write_rbuf(s, s->rwin, len - WINDOW_SIZE + s->rwin_start);
		s->rwin_start -= WINDOW_SIZE - len;
		if(s->rwin_start < 0)
		{
			printf("move_rwin : s->rwin_start became negative\n");
			return -1;
		}
	}
	else
	{
        write_rbuf(s, s->rwin + s->rwin_start, len);
		s->rwin_start += len;
	}

	uint32_t seq, next_seq = s->rseq[s->rseq_start] + len , i, pre_len = s->rseq_len;
    for(i = 0 ; i < pre_len ; i ++)
	{
		seq = s->rseq[s->rseq_start];
		if(seq < next_seq)
		{
			s->rseq_start = (s->rseq_start + 1) % WINDOW_NUM;
			s->rseq_len -= 1;
		}
		else if(seq == next_seq)
            return len;
		else
		{
            if(s->rseq_len == 0 || (next_seq < 2048*MSS && seq > 2048*MSS))
            {
                s->rseq_start = (s->rseq_start + 1) % WINDOW_NUM;
                s->rseq_len -= 1;
            }
            else
            {
			    s->rseq_start = (s->rseq_start - 1) % WINDOW_NUM;
			    s->rseq_len += 1;
			    s->rseq[s->rseq_start] = next_seq;	//	artificial seq , maybe cannot receive
            
                s->rlen[s->rseq_start] = UINT_MAX - seq + 1 + next_seq;

                printf("move_rwin : next_seq < seq case , crazy case, calculated len = %u\n", s->rlen[s->rseq_start]);

			    return len;
            }
		}
	}
	if(s->rseq[(s->rseq_start + s->rseq_len- 1 + WINDOW_NUM) % WINDOW_NUM] + s->rlen[(s->rseq_start + s->rseq_len - 1 + WINDOW_NUM) % WINDOW_NUM] != next_seq)
	{
		printf("move_rwin : next_seq not equal error\n");
		printf("seq=%u, len=%u, next_seq=%u\n", s->rseq[(s->rseq_start + s->rseq_len- 1 + WINDOW_NUM) % WINDOW_NUM], s->rlen[(s->rseq_start + s->rseq_len - 1 + WINDOW_NUM) % WINDOW_NUM], next_seq);
        printf("rseq_start = %d, rseq_len = %d\n", s->rseq_start, s->rseq_len);
        print_rseq(s);
        return -1;
	}

    s->rseq_start = (s->rseq_start - 1 + WINDOW_NUM) % WINDOW_NUM;
	s->rseq[s->rseq_start + s->rseq_len] = next_seq;	//	predictive seq , maybe receive
	s->rlen[s->rseq_start + s->rseq_len] = 0;
	s->rseq_len += 1;
    return len;
}

uint32_t TCPAssignment::eval_ACK(struct socket_fd *s)
{	
	uint32_t i, seq, len, pre_seq, pre_len;
	for(i = 0 ; i < (uint32_t)s->rseq_len ; i++)
	{
        if(i > 0)
        {
            pre_seq = seq;
            pre_len = len;
        }
		seq = s->rseq[(s->rseq_start + i) % WINDOW_NUM];
		len = (uint32_t)s->rlen[(s->rseq_start + i) % WINDOW_NUM];
		if(i > 0)
		{
			if(seq < pre_seq + pre_len)
			{
				printf("eval_ACK : error in rseq or rlen array\n");
				return 0;
			}
			else if(seq == pre_seq + pre_len)
			{
				pre_seq = seq;
				pre_len = len;
			}
			else
				break;
		}
	}
	if(i == 0)
		s->ack = (s->ack < seq + len) ? seq + len : s->ack;
	else
    {
        //printf("eval_ACK : s->ack = %u , pre_seq = %u, pre_len = %u, pre_seq+pre_len = %u\n", s->ack, pre_seq, pre_len, pre_seq + pre_len);
        if((int)s->ack < 0 && (int)(pre_seq + pre_len)>= 0)
            s->ack = pre_seq + pre_len;
		else
            s->ack = (s->ack < (pre_seq + pre_len)) ? (pre_seq + pre_len) : s->ack;
    }
    return s->ack;
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

    soc->domain = domain;
   	soc->pid = pid;
   	soc->protocol = protocol;
    soc->syscallUUID = syscallUUID;
	soc->is_passive = false;
	soc->status = 0;

    soc->rwin_start = 0;
    soc->rseq_start = 0;
    soc->rseq_len = 0;
    soc->rbuf_start = 0;
    soc->rbuf_len = 0;
	soc->read_blocked = false;

    int i = SBUF_NUM;
    while(--i >= 0)
        pthread_mutex_init(&soc->sbuf[i].occ_lock, NULL);

    soc->swin_start = 0;
    soc->swin_num = 1;
    soc->sbuf_end = 0;
    soc->sbuf_loc = 0;
    soc->rack = 0;
    soc->dup_cnt = 0;
    if(pthread_mutex_init(&soc->send_lock, NULL) != 0)
    {
        perror("create_socket - init mutex :");
        exit(1);
    }

    soc->whead.prev = NULL;
    soc->whead.next = &soc->wtail;
    soc->wtail.prev = &soc->whead;
    soc->wtail.next = NULL;

	soc->sent_time = 0;
	soc->rtt = 60000000000LL;
	soc->devrtt = 60000000000LL;

	soc->src_ip = 0;
	soc->des_ip = 0;
	soc->src_port = 0;
	soc->des_port = 0;
	
	soc->seq = 0;
	soc->ack = 0;

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

	pthread_mutex_lock(&fd_lock);
    
    soc->fd = createFileDescriptor(pid);

	soc->prev = socket_tail.prev;
	soc->next = &socket_tail;
	soc->prev->next = soc;
	socket_tail.prev = soc;
    
    /*
    struct socket_fd *trav;
    int fd1, fd2 = 2;
    bool inserted = false;
    for(trav = socket_head.next ; trav != &socket_tail ; trav = trav->next)
    {
        if(trav->pid != soc->pid)
            continue;
        fd1 = fd2;
        fd2 = trav->fd;
        if(fd2 < fd1 + 1)
        {
            printf("fild descripter sorting error\n");
            exit(0);
        }
        if(fd2 > fd1 + 1)
        {
            soc->fd = fd1 + 1;
            soc->next = trav;
            soc->prev = trav->prev;
            trav->prev->next = soc;
            trav->prev = soc;
            inserted = true;
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
    */

   	pthread_mutex_unlock(&fd_lock);
	
    return soc;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int protocol)
{
	socket_fd* soc = create_socket(syscallUUID, pid, domain, protocol);
	
    //printf("syscall_socket is called with pid = %d , allocated fd = %d\n", pid, soc->fd);
    returnSystemCall(syscallUUID, soc->fd);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog)
{
    //printf("syscall_listen is called with pid = %d , fd = %d\n", pid, fd);
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
    returnSystemCall(acc_info->syscallUUID, s->fd);
    free(acc_info);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, sockaddr *addr, socklen_t *addrlen)
{
    //printf("syscall_accept is called with pid = %d , fd = %d\n", pid, fd);
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
    socket_fd *f = get_socket(pid, fd);
    if(!f)
    {
        printf("bind : invalid fd\n");
        returnSystemCall(syscallUUID, -1);
        return;
    }
    if(f->is_passive)   //  bound already
    {
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
                 trav->addr == ((sockaddr_in*)addr)->sin_addr.s_addr) ) //  port overlapped
        {
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
    //printf("syscall_connect is called with pid = %d, fd = %d\n", pid, fd);
 	socket_fd *f = get_socket(pid, fd);

	if(!f)
	{
		printf("connect : invalid fd\n");
		returnSystemCall(syscallUUID, -1);
		return;
	}
	if(f->status != 0 && f->status != 1)
	{
		printf("connect : wrong socket status. status = %d\n", f->status);
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
	
	uint32_t seq_num = (f->seq)++ , ack_num = 0;
	seq_num = htonl(seq_num);
    f->ack = ack_num;
	uint8_t head_len = 5<<4;
	uint8_t flag = 0x2;
	uint16_t window = htons(WINDOW_SIZE);
	uint16_t urg_ptr = 0;
	
	writePacket(&src_ip, &des_ip, &src_port, &des_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);

	f->status = 3;
	f->src_ip = src_ip;
	f->des_ip = des_ip;
	f->src_port = src_port;
	f->des_port = des_port;
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count)
{
    //printf("syscall_read called\n");
    if(count == 0)
    {
        returnSystemCall(syscallUUID, 0);
        return;
    }
    socket_fd* s = get_socket(pid, fd);
    size_t readable;
	//if(s->rseq_len == 0 || (s->rseq_len == 1 && (s->rlen[s->rseq_start] == 0)))
	if(s->rbuf_len == 0)
    {
        //printf("read-block\n");
		readable = 0;	//	maybe can be deleted
		s->read_blocked = true;
		s->readUUID = syscallUUID;
		s->readbuf = (uint8_t*)buf;
		s->readlen = (int)count;
	}
	else
	{
        //printf("read-now\n");
		readable = s->rbuf_len;
		if(readable <= 0)
		{
			printf("syscall_read : readable <= 0 case\n");
			return;
		}
		size_t read = ((int)s->rbuf_len > (int)count) ? count : s->rbuf_len;
        //printf("syscall_read : %d %d %d\n", s->rbuf_l
		returnSystemCall(syscallUUID, read_rbuf(s, (uint8_t*)buf, (int)read));
		return;
	}	
}

void TCPAssignment::block_write(UUID syscallUUID, struct socket_fd *s, const void *buf, size_t len, size_t sent)
{
    writing *w = (writing*)malloc(sizeof(writing));
    w->syscallUUID = syscallUUID;
    w->buf = buf;
    w->count = len;
    w->sent = sent;
    
    w->prev = s->wtail.prev;
    w->next = &s->wtail;
    s->wtail.prev->next = w;
    s->wtail.prev = w;
}

void TCPAssignment::unblock_write(struct socket_fd *s)
{
    if(s->whead.next == &s->wtail)
    {
        printf("unblock_write : there is no blocked syscall_write\n");
        return;
    }
    //printf("unblock_write : blocked syscall_write exists\n");
    struct writing *w = s->whead.next;
    while(socket_write(w->syscallUUID, s, w->buf, w->count, w->sent, w))
    {
        struct writing *next = w->next;
        next->prev = &s->whead;
        w->prev->next = next;
        free(w);
        if(next == &s->wtail)
            break;
        w = next;
    }
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count)
{
    printf("syscall_write called with syscallUUID = %lu\n", syscallUUID);
    socket_fd *s = get_socket(pid, fd); 
    if(s->whead.next != &s->wtail)
    {
        block_write(syscallUUID, s, buf, count, 0);
        return;
    }

    socket_write(syscallUUID, s, buf, count, 0, NULL);
}

bool TCPAssignment::socket_write(UUID syscallUUID, struct socket_fd *soc, const void *buf, size_t count, size_t sent, struct writing *w)
{   
    //printf("socket_write called with syscallUUID = %lu\n", syscallUUID);
        
    /*
    uint32_t src_ip = soc->src_ip;
	uint32_t des_ip = soc->des_ip;
	uint16_t src_port = soc->src_port;
	uint16_t des_port = soc->des_port;
	uint8_t head_len = 5<<4;
	uint8_t flag = 0x10;
	uint16_t window = htons(WINDOW_SIZE);
	uint16_t urg_ptr = 0;
    */
    uint8_t *from = (uint8_t*)buf;
    
    size_t i = 0;
    
    //returnSystemCall(syscallUUID, count);
    while(i < count)
    {
        uint32_t seq_num = soc->seq;
        //uint32_t ack_num = soc->ack;
        size_t templen = (count - i > MSS)?MSS:(count - i);
        //printf("syscall_write : sent seq_num = %u\n", soc->seq);

        if(!add_sbuf(soc, from + i, templen, seq_num))
        {
            if(w)
            {
                w->buf = from + i;
                w->count = count - i;
                w->sent = i;
                return false;
            }
            block_write(syscallUUID, soc, from + i, count - i, i);
            return false;
        }
        /*  
	    seq_num = htonl(seq_num);
        ack_num = htonl(ack_num);
	    writePacket(&src_ip, &des_ip, &src_port, &des_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr, from + i, templen);
        */
        uint32_t sub = UINT_MAX - seq_num;
        if(templen > sub)
            soc->seq = templen - sub - 1;
        else
            soc->seq += templen;
        i += templen;
    }
    try_send(soc);
    returnSystemCall(syscallUUID, count + sent);
    printf("syscall_write returns with syscallUUID = %lu\n", syscallUUID);
    return true;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
    //printf("syscall_close called\n");
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
				uint32_t src_ip = soc->src_ip, des_ip = soc->des_ip;
				uint16_t src_port = soc->src_port, des_port = soc->des_port;
			
				uint32_t seq_num = (soc->seq)++, ack_num = soc->ack;
				seq_num = htonl(seq_num);

				uint8_t head_len = 5<<4 , flag = 0x1;	//	FIN
				uint16_t window = htons(WINDOW_SIZE), urg_ptr = 0;

				writePacket(&src_ip, &des_ip, &src_port, &des_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr);
			}
			break;
		case 5:	//	CLOSE_WAIT
			soc->status = 6;	//	LAST_ACK
			{
				uint32_t src_ip = soc->src_ip, des_ip = soc->des_ip;
				uint16_t src_port = soc->src_port, des_port = soc->des_port;
			
				uint32_t seq_num = (soc->seq)++, ack_num = soc->ack;
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
    struct socket_fd *soc = get_socket(pid,sockfd); 
    if(!(soc->des_ip) && !(soc->des_port))
    {
        returnSystemCall(syscallUUID, -1);
        return;
    }
    ((sockaddr_in*)addr)->sin_addr.s_addr = soc->des_ip;
    ((sockaddr_in*)addr)->sin_family=AF_INET;
    ((sockaddr_in*)addr)->sin_port = soc->des_port;
    returnSystemCall(syscallUUID, 0);
}

bool TCPAssignment::add_sbuf(struct socket_fd* s, uint8_t *payload, uint32_t size, uint32_t seq)
{
    int next = (s->sbuf_end + 1) % SBUF_NUM;
    if(pthread_mutex_trylock(&s->sbuf[s->sbuf_end].occ_lock) != 0)
        return false;
    /*if(next == s->swin_start)
    {
        printf("add_sbuf : sbuf is full\n");
        return;
    }*/
    struct sending *pac = &s->sbuf[s->sbuf_end];
    printf("add_sbuf : loc = %d, seq = %u, size = %u\n", s->sbuf_end, seq, size);
    //pac->payload = payload;
    memcpy(pac->payload, payload, size);
    pac->size = size;
    pac->seq = seq;
    pac->sent = false;
    s->sbuf_end = next;

    return true;
}

bool TCPAssignment::isfull_sbuf(struct socket_fd *s)
{
    return is_occupied(&s->sbuf[s->sbuf_end]);
}

bool TCPAssignment::is_occupied(struct sending *s)
{
    if(pthread_mutex_trylock(&s->occ_lock) != 0)
        return true;
    pthread_mutex_unlock(&s->occ_lock);
    return false;
}

void TCPAssignment::update_rtt(struct socket_fd *s)
{
	if(!s->sent_time)
		return;
	E::Time now = this->getHost()->getSystem()->getCurrentTime();
	E::Time gap = now - s->sent_time;
	s->rtt = (1 - ALPHA) * s->rtt + ALPHA * gap;
	if(s->rtt > gap)
		s->devrtt = (1 - BETA) * s->devrtt + BETA * (s->rtt - gap);
	else
		s->devrtt = (1 - BETA) * s->devrtt + BETA * (gap - s->rtt);
	s->sent_time = 0;
}

void TCPAssignment::try_send(struct socket_fd* s)
{
    /*
    if(pthread_mutex_trylock(&s->send_lock) != 0)
    {
        printf("try fail case\n");
        return;
    }
    */
    uint32_t src_ip = s->src_ip;
	uint32_t des_ip = s->des_ip;
	uint16_t src_port = s->src_port;
	uint16_t des_port = s->des_port;
	uint8_t head_len = 5<<4;
	uint8_t flag = 0x10;
	uint16_t window = htons(WINDOW_SIZE);
	uint16_t urg_ptr = 0;
    
    bool full = isfull_sbuf(s);
    //printf("try_send : isfull_sbuf returned %d\n", full);
    /*
    printf("[[[TEST OCCUPIED]]]\n");
    int i;
    for(i = 0 ; i < SBUF_NUM ; i ++)
        printf("occupied %d : %d\n", i, is_occupied(&s->sbuf[i]));
    */
    while(s->sbuf_loc != (s->swin_start + s->swin_num) % SBUF_NUM)
    {
        if(s->sbuf_loc == s->sbuf_end)
        {
            if(full)
                full = false;
            else
            {
                printf("try_send : because here\n");
                break;
            }
        }
        struct sending *pac = &s->sbuf[s->sbuf_loc];
        uint32_t seq_num = pac->seq;
        uint32_t ack_num = s->ack;
        size_t size = pac->size;

        printf("try_send : size = %lu, seq = %u, loc = %d, sbuf_end = %d\n", size, seq_num, s->sbuf_loc, s->sbuf_end);
	    seq_num = htonl(seq_num);
        ack_num = htonl(ack_num);
		
		if(!s->sent_time)
			s->sent_time = this->getHost()->getSystem()->getCurrentTime();
		capsule *cap = (capsule*)malloc(sizeof(capsule));
		cap->socket = s;
		cap->location = s->sbuf_loc;
		pac->timerUUID = this->addTimer(cap, s->rtt + K * s->devrtt);

	    writePacket(&src_ip, &des_ip, &src_port, &des_port, &seq_num, &ack_num, &head_len, &flag, &window, &urg_ptr, pac->payload, size);
        s->sbuf[s->sbuf_loc].sent = true;
        s->sbuf_loc = (s->sbuf_loc + 1) % SBUF_NUM;
        //s->swin_start = (s->swin_start + 1) % SBUF_NUM; //  temp for reliable transfer
    }
    printf("try_send end\n");

    //pthread_mutex_unlock(&s->send_lock);
}

void TCPAssignment::enqueue(queue* q, queue_node* enter){
	enter->prev = q->tail.prev;
	enter->next = &q->tail;
	enter->prev->next = enter;
	q->tail.prev = enter;

	(q->current_size)++;
}

TCPAssignment::queue_node* TCPAssignment::dequeue(queue* q){
	queue_node* ret = q->head.next;
	if(ret == &q->tail)
		return NULL;
	q->head.next = ret->next;
	ret->next->prev = &q->head;
	ret->prev = NULL;
	ret->next = NULL;
	return ret;
}

inline int TCPAssignment::check_four(struct socket_fd *soc, uint32_t src_ip, uint32_t des_ip, uint16_t src_port, uint16_t des_port)
{
    return (soc->src_ip == src_ip && soc->des_ip == des_ip && soc->src_port == src_port && soc->des_port == des_port);
}

void TCPAssignment::writePacket(uint32_t *src_ip, uint32_t *des_ip, uint16_t *src_port, uint16_t *des_port, uint32_t *seq_num, uint32_t *ack_num, uint8_t *head_len, uint8_t *flag, uint16_t *window_size, uint16_t *urg_ptr, uint8_t *payload, size_t size)
{
    Packet* p = this->allocatePacket(54+size);
    p->writeData(14+12, src_ip, 4);
    p->writeData(14+16, des_ip, 4);
    p->writeData(14+20, src_port,2);
    p->writeData(14+20+2, des_port,2);
    p->writeData(14+20+4, seq_num,4);
    p->writeData(14+20+8, ack_num,4);
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

    pthread_mutex_lock(&fd_lock);

	removeFileDescriptor(pid, fd);

    socket_fd* pr = soc->prev;
    pr->next = soc->next;
    soc->next->prev = pr;
    free(soc);

    pthread_mutex_unlock(&fd_lock);

	return 0;
}

//namespace E closing parenthesis
}
