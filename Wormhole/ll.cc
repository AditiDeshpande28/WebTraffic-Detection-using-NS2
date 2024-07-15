/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) 1997 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Daedalus Research
 *	Group at the University of California Berkeley.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Contributed by the Daedalus Research Group, http://daedalus.cs.berkeley.edu
 */

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /cvsroot/nsnam/ns-2/mac/ll.cc,v 1.47 2010/03/08 05:54:51 tom_henderson Exp $ (UCB)";
#endif

#include <errmodel.h>
#include <mac.h>
#include <ll.h>
#include <address.h>
#include <dsr/hdr_sr.h>

int hdr_ll::offset_;

static class LLHeaderClass : public PacketHeaderClass {
public:
	LLHeaderClass()	: PacketHeaderClass("PacketHeader/LL",
					    sizeof(hdr_ll)) {
		bind_offset(&hdr_ll::offset_);
	}
} class_hdr_ll;


static class LLClass : public TclClass {
public:
	LLClass() : TclClass("LL") {}
	TclObject* create(int, const char*const*) {
		return (new LL);
	}
} class_ll;


LL::LL() : LinkDelay(), seqno_(0), ackno_(0), macDA_(0), ifq_(0),
	mac_(0), lanrouter_(0), arptable_(0), varp_(0),
	downtarget_(0), uptarget_(0)
{
	bind("macDA_", &macDA_);
// Following three lines for Wormhole to initilize wormhole peer list head
	wormhole_head.ll = NULL;
	wormhole_head.id = -1;
	wormhole_head.next = NULL;
}

int LL::command(int argc, const char*const* argv)
{
	Tcl& tcl = Tcl::instance();
	if (argc == 3) {
		if (strcmp(argv[1], "ifq") == 0) {
			ifq_ = (Queue*) TclObject::lookup(argv[2]);
			return (TCL_OK);
		}
		if(strcmp(argv[1], "arptable") == 0) {
                        arptable_ = (ARPTable*)TclObject::lookup(argv[2]);
                        assert(arptable_);
                        return TCL_OK;
                }
		if(strcmp(argv[1], "varp") == 0) {
                        varp_ = (VARPTable*)TclObject::lookup(argv[2]);
                        assert(varp_);
                        return TCL_OK;
                }
		if (strcmp(argv[1], "mac") == 0) {
			mac_ = (Mac*) TclObject::lookup(argv[2]);
                        assert(mac_);
			return (TCL_OK);
		}
		if (strcmp(argv[1], "down-target") == 0) {
			downtarget_ = (NsObject*) TclObject::lookup(argv[2]);
			return (TCL_OK);
		}
		if (strcmp(argv[1], "up-target") == 0) {
			uptarget_ = (NsObject*) TclObject::lookup(argv[2]);
			return (TCL_OK);
		}
		if (strcmp(argv[1], "lanrouter") == 0) {
			lanrouter_ = (LanRouter*) TclObject::lookup(argv[2]);
			return (TCL_OK);
		}
//The following block of Else if for Wormhole Attack
		else if( strcmp( argv[1], "wormhole-peer" ) == 0 ) {
			wormhole_peer* wp = (wormhole_peer*) malloc( sizeof( wormhole_peer ) );
			if( !wp ) {
fprintf( stderr, "(%03d) - LL::command - error allocating memory for new wormhole peer!" );
exit(-1);
			}
			// init fields
		wp->ll = (LL *) TclObject::lookup( argv[2] );
			wp->id = wp->ll->mac_->addr();

			// insert at head of list
			wp->next = wormhole_head.next;
			wormhole_head.next = wp;

printf( "(%03d) - LL::command - added %d to wormhole peer list\n", mac_->addr(), wp->id );
			return TCL_OK;
		}

}
	else if (argc == 2) {
		if (strcmp(argv[1], "ifq") == 0) {
			tcl.resultf("%s", ifq_->name());
			return (TCL_OK);
		}
		if (strcmp(argv[1], "mac") == 0) {
			tcl.resultf("%s", mac_->name());
			return (TCL_OK);
		}
		if (strcmp(argv[1], "down-target") == 0) {
			tcl.resultf("%s", downtarget_->name());
			return (TCL_OK);
		}
		if (strcmp(argv[1], "up-target") == 0) {
			tcl.resultf("%s", uptarget_->name());
			return (TCL_OK);
		}
	}
	return LinkDelay::command(argc, argv);
}



void LL::recv(Packet* p, Handler* /*h*/)
{
	hdr_cmn *ch = HDR_CMN(p);
	//char *mh = (char*) HDR_MAC(p);
	//struct hdr_sr *hsr = HDR_SR(p);

	/*
	 * Sanity Check
	 */
	assert(initialized());

	//if(p->incoming) {
	//p->incoming = 0;
	//}
	// XXXXX NOTE: use of incoming flag has been depracated; In order to track direction of pkt flow, direction_ in hdr_cmn is used instead. see packet.h for details.

	// If direction = UP, then pass it up the stack
	// Otherwise, set direction to DOWN and pass it down the stack
	if(ch->direction() == hdr_cmn::UP) {
		//if(mac_->hdr_type(mh) == ETHERTYPE_ARP)
		if(ch->ptype_ == PT_ARP)
			arptable_->arpinput(p, this);
		else
			uptarget_ ? sendUp(p) : drop(p);
		return;
	}

	ch->direction() = hdr_cmn::DOWN;
	sendDown(p);
}


void LL::sendDown(Packet* p)
{	
	hdr_cmn *ch = HDR_CMN(p);
	hdr_ip *ih = HDR_IP(p);

	//following three lines for Wormhole Attack
	int is_broadcast = 0;
	int unicast_addr = -1;
	int is_routing = 0;

	nsaddr_t dst = (nsaddr_t)Address::instance().get_nodeaddr(ih->daddr());
	//nsaddr_t dst = ih->dst();
	hdr_ll *llh = HDR_LL(p);
	char *mh = (char*)p->access(hdr_mac::offset_);
	
	llh->seqno_ = ++seqno_;
	llh->lltype() = LL_DATA;

	mac_->hdr_src(mh, mac_->addr());
	mac_->hdr_type(mh, ETHERTYPE_IP);
	int tx = 0;
	
	switch(ch->addr_type()) {

	case NS_AF_ILINK:
		mac_->hdr_dst((char*) HDR_MAC(p), ch->next_hop());
// check next hop for wormhole peer / broadcast
		if( ch->next_hop() == MAC_BROADCAST )
			is_broadcast = 1;
		else
			unicast_addr = ch->next_hop();
// till here for WormHole
		break;

	case NS_AF_INET:
		dst = ch->next_hop();
		/* FALL THROUGH */
		
	case NS_AF_NONE:
		//From here for Wormhole 
		if (IP_BROADCAST == (u_int32_t) dst)
		{
		mac_->hdr_dst((char*) HDR_MAC(p), MAC_BROADCAST);
			is_broadcast = 1;
			break;
		}
		else {
			unicast_addr = dst;
		}
		// till here for Wormhole

		/* Assuming arptable is present, send query */
		if (arptable_) {
			tx = arptable_->arpresolve(dst, p, this);
			break;
		}
		//if (varp_) {
		//tx = varp_->arpresolve(dst, p);
		//break;
			
		//}			
		/* FALL THROUGH */

	default:
		
		int IPnh = (lanrouter_) ? lanrouter_->next_hop(p) : -1;
		if (IPnh < 0)
			mac_->hdr_dst((char*) HDR_MAC(p),macDA_);
		else if (varp_)
			tx = varp_->arpresolve(IPnh, p);
		else
			mac_->hdr_dst((char*) HDR_MAC(p), IPnh);
		break;
	}
	
	if (tx == 0) {
//from here for Wormhole attack
		Scheduler& s = Scheduler::instance();
// wormhole decision point (decide if this packet is going throught the wormhole or not)
		if( wormhole_head.next ) {
		if( is_broadcast ) {
		// send a copy to each wormhole peer
		wormhole_peer *wp = &wormhole_head;
		while( wp->next ) {
		wp = wp->next;
		Packet *p_copy = p->copy();
	hdr_cmn::access(p_copy)->direction() = hdr_cmn::UP;
	s.schedule( wp->ll, p_copy, delay_ );
		}

	// AND send it out our "real" interface (and gather stats)
	if( is_routing ) {
	routing_packet_count++;
	routing_byte_count += ch->size_;
	}
	else {
	data_packet_count++;
	data_byte_count += ch->size_;
	}
	s.schedule(downtarget_, p, delay_);
	return;
	}
	else {
	// scan through the list to see if it is for a wormhole peer
	wormhole_peer *wp_curr = wormhole_head.next;
	wormhole_peer *wp_prev = &wormhole_head;
	while( wp_curr ) {
	if( wp_curr->id == unicast_addr ) {
// if we found a match then send the packet too this wormhole peer only
hdr_cmn::access(p)->direction() = hdr_cmn::UP;
s.schedule( wp_curr->ll, p, delay_ );
// move this wormhole peer to the front of the list
// (optimizes many unicasts to the same peers)
wp_prev->next = wp_curr->next;
wp_curr->next = wormhole_head.next;
wormhole_head.next = wp_curr;
return;
}
					
// otherwise keep looking through list
wp_prev = wp_curr;
wp_curr = wp_curr->next;
}
				
// fall through if we don't find a matching wormhole peer
}
}
		
// let mac decide when to take a new packet from the queue.
		if( is_routing ) {
			routing_packet_count++;
			routing_byte_count += ch->size_;
		}
		else {
			data_packet_count++;
			data_byte_count += ch->size_;
		}
		s.schedule(downtarget_, p, delay_);
	}
}
//Wormhole till here
void LL::sendUp(Packet* p)
{

	Scheduler& s = Scheduler::instance();
	if (hdr_cmn::access(p)->error() > 0)
		drop(p);
	else
		s.schedule(uptarget_, p, delay_);
}

inline void LL::hdr_dst(Packet *, int)
{}
