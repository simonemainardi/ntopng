/*
 *
 * (C) 2014-17 - ntop.org
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

#ifndef _STATUS_INFORMATION_H_
#define _STATUS_INFORMATION_H_

#include "ntop_includes.h"

class StatusInformation {
  typedef struct {
    char *status_str;
    HostStatus status;
    UT_hash_handle hh;    
  } status_mapping_t;
  typedef std::map<const char *, HostStatus> StatusBits;

 private:
  u_int8_t status, alert;
  static status_mapping_t *status_mapping;
  static void initMapping();
  static void addMapping(const char *k, HostStatus hs);

 public:
  StatusInformation();

  inline bool isAnomalous()                       { return status != 0 || alert != 0;   };

  /* Statuses are set from C */

  inline bool getStatus(HostStatus host_status)   { return status & (1 << host_status); };
  inline void setStatus(HostStatus host_status)   { status |= 1 << host_status;         };
  inline void clearStatus(HostStatus host_status) { status &= ~(1 << host_status);      };

  /* Alerts for statuses are set from Lua */
  inline bool getStatusAlerted(HostStatus host_status) { return alert & (1 << host_status); };
  void setStatusAlerted(const char *k);
  void clearStatusAlerted(const char *k);

  void lua(lua_State* vm);
};

#endif /* _STATUS_INFORMATION_H_ */
