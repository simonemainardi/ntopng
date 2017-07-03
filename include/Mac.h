/*
 *
 * (C) 2013-17 - ntop.org
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

#ifndef _MAC_H_
#define _MAC_H_

#include "ntop_includes.h"

class Mac : public GenericHashEntry, public GenericTrafficElement {
 private:
  u_int8_t mac[6];
  const char * manuf;
  u_int16_t vlan_id;
  bool source_mac:1, special_mac:1, bridge_seen_iface[2] /* , notused:4 */;
  ArpStats arp_stats;

 public:
  Mac(NetworkInterface *_iface, u_int8_t _mac[6], u_int16_t _vlanId);
  ~Mac();

  inline u_int16_t getNumHosts()               { return getUses();            }
  inline void incUses()                        { GenericHashEntry::incUses(); if(source_mac && (getUses() == 1)) iface->incNumL2Devices(); }
  inline void decUses()                        { GenericHashEntry::decUses(); if(source_mac && (getUses() == 0)) iface->decNumL2Devices(); }
  inline bool isSpecialMac()                   { return(special_mac);         }
  inline bool isSourceMac()                    { return(source_mac);          }
  inline void setSourceMac() {
    if (!source_mac && !special_mac) {
      source_mac = true;
      if(getUses() > 0) iface->incNumL2Devices();
    }
  }
  inline u_int32_t key()                       { return(Utils::macHash(mac)); }
  inline u_int8_t* get_mac()                   { return(mac);                 }
  inline const char * const get_manufacturer() { return manuf ? manuf : NULL; }
  inline u_int16_t get_vlan_id() { return(vlan_id);             }
  inline bool isNull()           { for(int i=0; i<6; i++) { if(mac[i] != 0) return(false); } return(true); }      
    
  bool equal(u_int16_t _vlanId, const u_int8_t _mac[6]);
  inline void incSentStats(u_int64_t num_pkts, u_int64_t num_bytes)  {
    sent.incStats(num_pkts, num_bytes);
    if(first_seen == 0) first_seen = iface->getTimeLastPktRcvd();
    last_seen = iface->getTimeLastPktRcvd();
  }
  inline void incRcvdStats(u_int64_t num_pkts, u_int64_t num_bytes) {
    rcvd.incStats(num_pkts, num_bytes);
  }

  inline void incSentArpRequests()   { arp_stats.sent_requests++;         }
  inline void incSentArpReplies()    { arp_stats.sent_replies++;          }
  inline void incRcvdArpRequests()   { arp_stats.rcvd_requests++;         }
  inline void incRcvdArpReplies()    { arp_stats.rcvd_replies++;          }
  inline void setSeenIface(u_int8_t idx)  { bridge_seen_iface[idx & 0x01] = 1; setSourceMac(); }
  inline bool isSeenIface(u_int8_t idx)   { return(bridge_seen_iface[idx & 0x01]); }
  inline u_int64_t getNumSentArp()   { return (u_int64_t)arp_stats.sent_requests + arp_stats.sent_replies; }
  inline u_int64_t getNumRcvdArp()   { return (u_int64_t)arp_stats.rcvd_requests + arp_stats.rcvd_replies; }

  bool idle();
  void lua(lua_State* vm, bool show_details, bool asListElement);
  inline char* get_string_key(char *buf, u_int buf_len) { return(Utils::formatMac(mac, buf, buf_len)); }
  inline int16_t findAddress(AddressTree *ptree)        { return ptree ? ptree->findMac(mac) : -1;     };

  char* serialize();
  void deserialize(char *key, char *json_str);
  json_object* getJSONObject();
};

#endif /* _MAC_H_ */

