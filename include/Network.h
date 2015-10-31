/*
 *
 * (C) 2013-15 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef _NETWORK_H_
#define	_NETWORK_H_

#include "ntop_includes.h"

class Network : public GenericHashEntry {
 private:
     u_int16_t num_uses;
     u_int16_t vlanId;
     u_int16_t networkId;
     u_int64_t inner_bytes, ingress_bytes, egress_bytes;
 public:
     void incUses() { num_uses++; }
     void decUses() { num_uses--; }
     void incEgressBytes(u_int64_t bytes){egress_bytes += bytes;};
     void incIngressBytes(u_int64_t bytes){ingress_bytes += bytes;};
     void incInnerBytes(u_int64_t bytes){inner_bytes += bytes;};
     Network(NetworkInterface *_iface, u_int16_t vlanId, u_int16_t networkId);
     inline u_int16_t get_vlan_id()           { return(vlanId);        };
     inline u_int16_t get_network_id()        { return(networkId);     };
     u_int32_t key();
     bool idle();
};

#endif	/* _NETWORK_H_ */