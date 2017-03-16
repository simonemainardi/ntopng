/*
 *
 * (C) 2015-17 - ntop.org
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

#define MAX_ALERT_HEADER_FIELD_LEN 32

/* *************************************** */

bool Alert::parse_header(json_object *obj) {
  json_object *header, *content;

  if(json_object_object_get_ex(obj, "header", &header)) {

    if(json_object_object_get_ex(header, "source_type", &content))
      source_type = strndup(json_object_get_string(content), MAX_ALERT_HEADER_FIELD_LEN),
	hash_key += Utils::string_hash(source_type);

    if(json_object_object_get_ex(header, "source_value", &content))
      source_value = strndup(json_object_get_string(content), MAX_ALERT_HEADER_FIELD_LEN),
	hash_key += Utils::string_hash(source_value);

    if(json_object_object_get_ex(header, "target_type", &content))
      target_type = strndup(json_object_get_string(content), MAX_ALERT_HEADER_FIELD_LEN),
	hash_key += Utils::string_hash(target_type);

    if(json_object_object_get_ex(header, "target_value", &content))
      target_value = strndup(json_object_get_string(content), MAX_ALERT_HEADER_FIELD_LEN),
	hash_key += Utils::string_hash(target_value);

    if(json_object_object_get_ex(header, "alert_id", &content))
      alert_id = strndup(json_object_get_string(content), MAX_ALERT_HEADER_FIELD_LEN),
	hash_key += Utils::string_hash(alert_id);

    if(json_object_object_get_ex(header, "alert_type", &content))
      alert_type = strndup(json_object_get_string(content), MAX_ALERT_HEADER_FIELD_LEN);

    if(json_object_object_get_ex(header, "alert_severity", &content))
      alert_severity = strndup(json_object_get_string(content), MAX_ALERT_HEADER_FIELD_LEN);

    if(json_object_object_get_ex(header, "timestamp", &content))
      timestamp = json_object_get_int(content);

    if(json_object_object_get_ex(header, "status", &content))
      status = strndup(json_object_get_string(content), MAX_ALERT_HEADER_FIELD_LEN);

  } else {
    return false;
  }

  if((!source_type && !target_type) || (!source_value && !target_value))
    return false;

  /* Prevents same source and target */
  if(source_type && target_type && !strcmp(source_type, target_type)
     && source_value && target_value && !strcmp(source_value, target_value))
    return false;

  return (((source_type && source_value) || (target_type && target_value)));
}

/* *************************************** */

Alert::Alert(const Alert &alert) : GenericHashEntry(NULL) {
  source_type = source_value = NULL;
  target_type = target_value = NULL;
  alert_type = alert_severity = NULL;
  status = alert_id = NULL;
  json = NULL;

  if(alert.source_type)
    source_type = strdup(alert.source_type);

  if(alert.source_value)
    source_value = strdup(alert.source_value);

  if(alert.target_type)
    target_type = strdup(alert.target_type);

  if(alert.target_value)
    target_value = strdup(alert.target_value);

  if(alert.alert_type)
    alert_type = strdup(alert.alert_type);

  if(alert.alert_severity)
    alert_severity = strdup(alert.alert_severity);

  if(alert.status)
    status = strdup(alert.status);

  if(alert.alert_id)
    alert_id = strdup(alert.alert_id);

  if(alert.json)
    json = strdup(alert.json);

  timestamp = alert.timestamp;
  valid_json = alert.valid_json;
  hash_key = alert.hash_key;
  source_counter_increased = alert.source_counter_increased,
    target_counter_increased = alert.target_counter_increased;  
}

/* *************************************** */

Alert::~Alert() {
  if(source_type)    free(source_type);
  if(source_value)   free(source_value);
  if(target_type)    free(target_type);
  if(target_value)   free(target_value);
  if(alert_type)     free(alert_type);
  if(alert_severity) free(alert_severity);
  if(status)         free(status);
  if(alert_id)       free(alert_id);
}

/* *************************************** */

Alert::Alert(const char *alert_json) : GenericHashEntry(NULL) {
  json_object *o;
  enum json_tokener_error jerr = json_tokener_success;

  source_counter_increased = target_counter_increased = false;

  source_type = source_value = target_type = target_value = NULL;
  alert_type = alert_severity = NULL;
  status = alert_id = NULL;
  json = NULL;
  timestamp = 0;
  hash_key = 0;

  valid_json = true;

  if(!alert_json)
    valid_json = false;

  if((o = json_tokener_parse_verbose(alert_json, &jerr)) == NULL) {
    ntop->getTrace()->traceEvent(TRACE_WARNING, "JSON Alert parse error [%s] %s",
				 json_tokener_error_desc(jerr),
				 alert_json);
    valid_json = false;
  } else
    json = alert_json;

  if(valid_json) {
    if(!parse_header(o))
      valid_json = false;
  }

};

/* *************************************** */

const char *Alert::getHeaderField(const char *field_name) const {
  if(!field_name || field_name[0] == '\0')
    return NULL;

  if(!strncmp(field_name, "source_type", strlen("source_type")))
    return source_type;

  if(!strncmp(field_name, "source_value", strlen("source_value")))
    return source_value;

  if(!strncmp(field_name, "target_type", strlen("target_type")))
    return target_type;

  if(!strncmp(field_name, "target_value", strlen("target_value")))
    return target_value;

  if(!strncmp(field_name, "alert_type", strlen("alert_type")))
    return alert_type;

  if(!strncmp(field_name, "alert_severity", strlen("alert_severity")))
    return alert_severity;

  if(!strncmp(field_name, "status", strlen("status")))
    return status;

  if(!strncmp(field_name, "alert_id", strlen("alert_id")))
    return alert_id;

  return NULL;
};

/* *************************************** */

bool Alert::equal(const Alert *alert) const {
  bool null1, null2;
  /* Two engaged alerts are considered equal if they match on the fields below */
  const char *equality_fields[] = {"source_type", "source_value", "target_type", "target_value", "alert_id", NULL};
  const char *field = equality_fields[0];
  int i = 0;

  if(!alert || !valid_json)
    return false;

  while(field) {
    null1 = (getHeaderField(field) == NULL);
    null2 = (alert->getHeaderField(field) == NULL);

    if ((null1 != null2)
	||(!null1 && !null2
	   && strcmp(getHeaderField(field), alert->getHeaderField(field))))
      return false;

    field = equality_fields[++i];
  }

  return true;
}
