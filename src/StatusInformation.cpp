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

#include "ntop_includes.h"

/* *************************************** */

StatusInformation::StatusInformation() {
  status = alert = 0;
  if(status_mapping == NULL)
    initMapping();
}

/* *************************************** */

json_object* StatusInformation::getJSONObject() {
  json_object *my_object;

  my_object = json_object_new_object();

  json_object_object_add(my_object, "status", json_object_new_int(status));
  json_object_object_add(my_object, "alert", json_object_new_int(alert));

  return my_object;
}

/* *************************************** */

void StatusInformation::deserialize(json_object *o) {
  json_object *obj;

  if(!o) return;

  if(json_object_object_get_ex(o, "status", &obj))  status = json_object_get_int(obj);
  if(json_object_object_get_ex(o, "alert", &obj))   alert = json_object_get_int(obj);
}

/* *************************************** */

void StatusInformation::setStatusAlerted(const char *k) {
  status_mapping_t *s = NULL;

  HASH_FIND_STR(status_mapping, k, s);

  if(s) {
    alert |= 1 << s->status;
  }
}

/* *************************************** */

void StatusInformation::clearStatusAlerted(const char *k) {
  status_mapping_t *s = NULL;

  HASH_FIND_STR(status_mapping, k, s);

  if(s) {
    alert &= ~(1 << s->status);
  }
}
/* *************************************** */

void StatusInformation::lua(lua_State *vm) {
  status_mapping_t *current, *tmp;

  if(!vm)
    return;

  lua_newtable(vm);

  HASH_ITER(hh, status_mapping, current, tmp) {
    lua_newtable(vm);

    lua_push_bool_table_entry(vm, "status", getStatus(current->status));
    lua_push_bool_table_entry(vm, "alert", getStatusAlerted(current->status));
    lua_push_str_table_entry(vm, "str", current->status_str);

    lua_pushstring(vm, current->status_str);
    lua_insert(vm, -2);
    lua_settable(vm, -3);
  }

  lua_pushstring(vm, "status");
  lua_insert(vm, -2);
  lua_settable(vm, -3);
}

/* *************************************** */

void StatusInformation::addMapping(const char *k, HostStatus hs) {
  status_mapping_t *sm = (status_mapping_t*)calloc(1, sizeof(StatusInformation::status_mapping_t));
  if(sm) {
    sm->status_str = strdup(k);
    sm->status = hs;
    HASH_ADD_STR(status_mapping, status_str, sm);
  }
}

/* *************************************** */

void StatusInformation::initMapping() {
  StatusInformation::addMapping("syn_flooder", host_status_syn_flooder);
  StatusInformation::addMapping("syn_flood_target", host_status_syn_flood_target);
  StatusInformation::addMapping("scanner", host_status_scanner);
  StatusInformation::addMapping("scan_target", host_status_scan_target);
  StatusInformation::addMapping("above_quota", host_status_above_quota);
}

/* *************************************** */

StatusInformation::status_mapping_t *StatusInformation::status_mapping = NULL;
