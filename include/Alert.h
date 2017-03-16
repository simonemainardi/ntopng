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

#ifndef _ALERT_H_
#define _ALERT_H_

#include "ntop_includes.h"

class Alert : public GenericHashEntry {
 private:
  u_int32_t hash_key;
  bool valid_json;
  const char *json;

  bool source_counter_increased, target_counter_increased; /* Statuses for engaged alerts counters */

  char *source_type, *source_value;
  char *target_type, *target_value;
  char *alert_type, *alert_severity;
  time_t timestamp;
  char *status; /* engaged, released, or occurred */
  char *alert_id;

  bool parse_header(json_object *obj);
 public:
  Alert(const char *alert_json);
  Alert(const Alert &alert);
  virtual ~Alert();

  bool equal(const Alert *alert)     const;
  inline bool isValid() const        { return valid_json; };
  inline time_t getTimestamp() const { return timestamp;  };
  inline const char *getJSON() const { return json;       };
  const char *getHeaderField(const char *field_name) const;

  inline void sourceCounterIncreased()    { source_counter_increased = true; };
  inline void targetCounterIncreased()    { target_counter_increased = true; };
  inline bool isSourceCounterIncreased()  { return source_counter_increased; }
  inline bool isTargetCounterIncreased()  { return target_counter_increased; }

  bool idle()     { return false;    };
  u_int32_t key() { return hash_key; };
};

#endif /* _ALERT_H_ */
