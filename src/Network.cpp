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

#include "ntop_includes.h"

/* *************************************** */

Network::Network(NetworkInterface *_iface,
        u_int16_t _vlanId, u_int16_t _networkId) : GenericHashEntry(_iface){
    num_uses = 0;
    vlanId = _vlanId;
    networkId = _networkId;
    inner_bytes = 0, ingress_bytes = 0, egress_bytes = 0;    
}

/* *************************************** */
u_int32_t Network::key() {
  u_int32_t k = vlanId + networkId;
  return(k);
}

bool Network::idle() {
  if(num_uses > 0) return(false);
  if(!iface->is_purge_idle_interface()) return(false);
  return true;
};