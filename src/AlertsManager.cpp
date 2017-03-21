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

/* **************************************************** */

static void* dequeueLoop(void* ptr) {
  return(((AlertsManager*)ptr)->dequeueLoop());
}

/* **************************************************** */

void* AlertsManager::dequeueLoop() {
  bool found;
  char *json_alert;

  ntop->getTrace()->traceEvent(TRACE_NORMAL, "Executing %s()", __FUNCTION__);

  if(ntop->getGlobals()->isShutdown() || ntop->getPrefs()->are_alerts_disabled())
    return(NULL);

  while(!ntop->getGlobals()->isShutdown()) {
    found = false;

    if(alertsQueue->dequeue((void**)&json_alert)) {
      found = true;

      processDequeuedAlert(json_alert);

      if(json_alert) free(json_alert);
    }

    if(found == 0) {
      processInactive();
      sleep(1);
    }

  }

  return(NULL);
}

/* **************************************************** */

int AlertsManager::processDequeuedAlert(const char *json_alert) {
  Alert alert(json_alert);

  if(!alert.isValid()) {
    ntop->getTrace()->traceEvent(TRACE_DEBUG, "Alert is not valid JSON, skipping [%s]", json_alert ? json_alert : "");
    return -1;
  }

  const char *status;

  ntop->getTrace()->traceEvent(TRACE_DEBUG, "Alert JSON [%s]", json_alert ? json_alert : NULL);
  ntop->getTrace()->traceEvent(TRACE_DEBUG, "Alert [source_type: %s] [source_value: %s] "
			       "[target_type: %s] [target_value: %s] "
			       "[alert_type: %s] [alert_severity: %s] "
			       "[timestamp: %i]",
			       alert.getHeaderField("source_type")    ?  alert.getHeaderField("source_type")    : "NULL",
			       alert.getHeaderField("source_value")   ?  alert.getHeaderField("source_value")   : "NULL",
			       alert.getHeaderField("target_type")    ?  alert.getHeaderField("target_type")    : "NULL",
			       alert.getHeaderField("target_value")   ?  alert.getHeaderField("target_value")   : "NULL",
			       alert.getHeaderField("alert_type")     ?  alert.getHeaderField("alert_type")     : "NULL",
			       alert.getHeaderField("alert_severity") ?  alert.getHeaderField("alert_severity") : "NULL",
			       alert.getTimestamp()
			       );

  status = alert.getHeaderField("status");

  if(status && !strncmp(status, "engaged", strlen("engaged")))
    engageAlert(&alert);
  else if(status && !strncmp(status, "released", strlen("released")))
    releaseAlert(&alert);
  else
    storeAlert(&alert);

  return 0;
}

/* **************************************************** */

static bool inactive_walker(GenericHashEntry *alert, void *user_data) {
  AlertsManager *am = (AlertsManager*)user_data;
  Alert *a = (Alert*)alert;

  if(!am)
    return(true);

  if(!a)
    return(false);

  /* Try to increase as alert source/dest may have become active */
  am->incDecEngagedAlertsCounters(a, true /* counters++ */);

  return(false); /* false = keep on walking */
}

/* **************************************************** */

int AlertsManager::processInactive() {

  walk(inactive_walker, (void*)this);

  return 0;
}

/* **************************************************** */

struct engaged_count_info {
  char *type, *value;
  u_int num_matches;
};

/* **************************************************** */

static bool count_walker(GenericHashEntry *alert, void *user_data) {
  struct engaged_count_info *count_info = (struct engaged_count_info*)user_data;
  Alert *a = (Alert*)alert;

  if(!count_info)
    return(true);
  
  if(!a)
    return(false);

  if(a->getHeaderField("source_type") && count_info->type
     && a->getHeaderField("source_value") && count_info->value
     && !strcmp(a->getHeaderField("source_value"), count_info->value))
    count_info->num_matches++;

  if(a->getHeaderField("target_type") && count_info->type
     && a->getHeaderField("target_value") && count_info->value
     && !strcmp(a->getHeaderField("target_value"), count_info->value))
    count_info->num_matches++;

  return(false); /* false = keep on walking */
}

/* **************************************************** */

u_int32_t AlertsManager::getNumEngagedAlerts(Host *h) {
  u_int32_t ret = 0;
  struct engaged_count_info count_info;
  char host_buf[64];
  char *host_ip = NULL;

  if(!h || ! h->get_ip())
    return ret;

  host_ip = h->get_ip()->print(host_buf, sizeof(host_buf));
  if(host_ip && h->get_vlan_id())
    sprintf(&host_ip[strlen(host_ip)], "@%i", h->get_vlan_id());    

  count_info.type = (char*)"host", count_info.value = host_ip;
  count_info.num_matches = 0;

  disablePurge(); /* We're concurrent with the dequeueLoop */

  walk(count_walker, &count_info);

  enablePurge();

  return ret;
}

/* **************************************************** */

int AlertsManager::engageAlert(Alert *alert) {
  int rc;
  sqlite3_stmt *stmt = NULL;
  char query[STORE_MANAGER_MAX_QUERY];

  if(!store_initialized || !store_opened || !hasEmptyRoom() /* The engaged alerts cache is full */ )
    return -1;

  if(isEngaged(alert)) {
    rc = 1; /* Already engaged */
  } else {
    /* This alert is being engaged */

    snprintf(query, sizeof(query),
	     "INSERT INTO %s "
	     "(alert_id, alert_tstamp, alert_type, alert_severity, "
	     "source_type, source_value, target_type, target_value, is_engaged, alert_json) "
	     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?); ",
	     ALERTS_MANAGER_TABLE);

    m.lock(__FILE__, __LINE__);

    if(sqlite3_prepare(db, query, -1, &stmt, 0)) {
      ntop->getTrace()->traceEvent(TRACE_NORMAL, "SQL Error: prepare failed.");
      rc = -2;
      goto out;
    }

    if(sqlite3_bind_text(stmt,  1, alert->getHeaderField("alert_id"), -1, SQLITE_STATIC)
       || sqlite3_bind_int64(stmt, 2, static_cast<long int>(alert->getTimestamp()))
       || sqlite3_bind_text(stmt,  3, alert->getHeaderField("alert_type"), -1, SQLITE_STATIC)
       || sqlite3_bind_text(stmt,  4, alert->getHeaderField("alert_severity"), -1, SQLITE_STATIC)
       || sqlite3_bind_text(stmt,  5, alert->getHeaderField("source_type"), -1, SQLITE_STATIC)
       || sqlite3_bind_text(stmt,  6, alert->getHeaderField("source_value"), -1, SQLITE_STATIC)
       || sqlite3_bind_text(stmt,  7, alert->getHeaderField("target_type"), -1, SQLITE_STATIC)
       || sqlite3_bind_text(stmt,  8, alert->getHeaderField("target_value"), -1, SQLITE_STATIC)
       || sqlite3_bind_int64(stmt, 9, 1 /* 1 == is_engaged */)
       || sqlite3_bind_text(stmt, 10, alert->getJSON(), -1, SQLITE_STATIC)) {
      ntop->getTrace()->traceEvent(TRACE_NORMAL, "SQL Error: bind failed");
      rc = -3;
      goto out;
    }

    while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
      if(rc == SQLITE_ERROR) {
	ntop->getTrace()->traceEvent(TRACE_INFO, "SQL Error: step");
	rc = -4;
	goto out;
      }
    }

    rc = 0;

  out:
    if(stmt) sqlite3_finalize(stmt);
    m.unlock(__FILE__, __LINE__);

    if(rc == 0)
      setEngaged(alert); /* Only if the insert has been successful */
  }
  return rc;
}

/* **************************************************** */

int AlertsManager::releaseAlert(Alert *alert) {
  int rc, stmt_number = 1;
  sqlite3_stmt *stmt = NULL;
  char query[STORE_MANAGER_MAX_QUERY];

  if(!store_initialized || !store_opened)
    return -1;

  if(!isEngaged(alert)) {
    rc = 1; /* Cannot release a non-engaged alert */
  } else {
    /* This alert is being engaged */

    snprintf(query, sizeof(query),
	     "UPDATE %s SET is_engaged = ?, alert_tstamp_end = ? WHERE "
	     "alert_id = ? and is_engaged = ? "
	     "and source_type %s and source_value %s "
	     "and target_type %s and target_value %s ; ",
	     ALERTS_MANAGER_TABLE,
	     alert->getHeaderField("source_type") ? "= ?" : "is null",
	     alert->getHeaderField("source_value") ? "= ?" : "is null",
	     alert->getHeaderField("target_type") ? "= ?" : "is null",
	     alert->getHeaderField("target_value") ? "= ?" : "is null");

    m.lock(__FILE__, __LINE__);

    if(sqlite3_prepare(db, query, -1, &stmt, 0)) {
      ntop->getTrace()->traceEvent(TRACE_NORMAL, "SQL Error: prepare failed.");
      rc = -2;
      goto out;
    }

    if(sqlite3_bind_int64(stmt, stmt_number++, 0 /* 0 == NOT ENGAGED */)
       || sqlite3_bind_int64(stmt, stmt_number++, static_cast<long int>(alert->getTimestamp()))
       || sqlite3_bind_text(stmt,  stmt_number++, alert->getHeaderField("alert_id"), -1, SQLITE_STATIC)
       || sqlite3_bind_int64(stmt, stmt_number++, 1 /* 1 == was ENGAGED */)
       || (alert->getHeaderField("source_type")
	   && sqlite3_bind_text(stmt,  stmt_number++, alert->getHeaderField("source_type"), -1, SQLITE_STATIC))
       || (alert->getHeaderField("source_value")
	   && sqlite3_bind_text(stmt,  stmt_number++, alert->getHeaderField("source_value"), -1, SQLITE_STATIC))
       || (alert->getHeaderField("target_type")
	   && sqlite3_bind_text(stmt,  stmt_number++, alert->getHeaderField("target_type"), -1, SQLITE_STATIC))
       || (alert->getHeaderField("target_value")
	   && sqlite3_bind_text(stmt,  stmt_number++, alert->getHeaderField("target_value"), -1, SQLITE_STATIC))) {
      ntop->getTrace()->traceEvent(TRACE_NORMAL, "SQL Error: bind failed");
      rc = -3;
      goto out;
    }

    while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
      if(rc == SQLITE_ERROR) {
	ntop->getTrace()->traceEvent(TRACE_INFO, "SQL Error: step");
	rc = -4;
	goto out;
      }
    }

    rc = 0;

  out:
    if(stmt) sqlite3_finalize(stmt);
    m.unlock(__FILE__, __LINE__);

    if(rc == 0)
      setReleased(alert); /* Here only if db write has been successful */
  }
  return rc;
}

/* **************************************************** */

int AlertsManager::storeAlert(Alert *alert) {
  int rc;
  sqlite3_stmt *stmt = NULL;
  char query[STORE_MANAGER_MAX_QUERY];

  if(!store_initialized || !store_opened)
    return -1;

  snprintf(query, sizeof(query),
	   "INSERT INTO %s "
	   "(alert_tstamp, alert_type, alert_severity, "
	   "source_type, source_value, target_type, target_value, is_engaged, alert_json) "
	   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?); ",
	   ALERTS_MANAGER_TABLE);

  m.lock(__FILE__, __LINE__);

  if(sqlite3_prepare(db, query, -1, &stmt, 0)) {
    ntop->getTrace()->traceEvent(TRACE_NORMAL, "SQL Error: prepare failed.");
    rc = -2;
    goto out;
  }

  if(sqlite3_bind_int64(stmt, 1, static_cast<long int>(alert->getTimestamp()))
     || sqlite3_bind_text(stmt,  2, alert->getHeaderField("alert_type"), -1, SQLITE_STATIC)
     || sqlite3_bind_text(stmt,  3, alert->getHeaderField("alert_severity"), -1, SQLITE_STATIC)
     || sqlite3_bind_text(stmt,  4, alert->getHeaderField("source_type"), -1, SQLITE_STATIC)
     || sqlite3_bind_text(stmt,  5, alert->getHeaderField("source_value"), -1, SQLITE_STATIC)
     || sqlite3_bind_text(stmt,  6, alert->getHeaderField("target_type"), -1, SQLITE_STATIC)
     || sqlite3_bind_text(stmt,  7, alert->getHeaderField("target_value"), -1, SQLITE_STATIC)
     || sqlite3_bind_int64(stmt, 8, 0 /* 0 == NOT engaged */)
     || sqlite3_bind_text(stmt,  9, alert->getJSON(), -1, SQLITE_STATIC)) {
    ntop->getTrace()->traceEvent(TRACE_NORMAL, "SQL Error: bind failed");
    rc = -3;
    goto out;
  }

  while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
    if(rc == SQLITE_ERROR) {
      ntop->getTrace()->traceEvent(TRACE_INFO, "SQL Error: step");
      rc = -4;
      goto out;
    }
  }

  rc = 0;
 out:
  if(stmt) sqlite3_finalize(stmt);
  m.unlock(__FILE__, __LINE__);
  
  if(rc == 0)
    setStored(alert); /* Here only if db write has been successful */

  return rc;
}

/* **************************************************** */

void AlertsManager::incDecEngagedAlertsCounters(Alert *alert, bool increase) {
  const char *source_type = NULL, *source_value = NULL,
    *target_type = NULL, *target_value = NULL;

  if(!alert)
    return;

  /* Hosts require engaged alert counters to be in sync */

  if(!increase /* Implies release thus there's no need to check */
     || !alert->isSourceCounterIncreased()) {
    source_type = alert->getHeaderField("source_type");
    source_value = alert->getHeaderField("source_value");

    if(source_type && source_value
       && !strncmp(source_type, "host", strlen("host")))
      if(StoreManager::iface
	 && StoreManager::iface->incDecHostEngagedAlertsCounter(source_value, increase)
	 && increase)
	alert->sourceCounterIncreased(); /* Alert source is currently in ntopng hosts cache */
  }

  if(!increase
     || !alert->isTargetCounterIncreased()) {
    target_type = alert->getHeaderField("target_type");
    target_value = alert->getHeaderField("target_value");

    if(target_type && target_value
       && !strncmp(target_type, "host", strlen("host")))
      if(StoreManager::iface
	 && StoreManager::iface->incDecHostEngagedAlertsCounter(target_value, increase)
	 && increase)
	alert->targetCounterIncreased(); /* Alert target is currently in ntopng hosts cache */
  }
}

/* **************************************************** */

void AlertsManager::updateStatusInformation(Alert *alert, bool status_alerted) {
  const char *source_type = NULL, *source_value = NULL,
    *target_type = NULL, *target_value = NULL;
  const char *alert_type = NULL;

  if(!alert || (alert_type = alert->getHeaderField("alert_type")) == NULL)
    return;

  source_type = alert->getHeaderField("source_type");
  source_value = alert->getHeaderField("source_value");

  /* Hosts require engaged alert counters to be in sync */

  if(source_type && source_value
     && !strncmp(source_type, "host", strlen("host"))) {
    if(StoreManager::iface)
      StoreManager::iface->hostStatusAlerted(source_value, alert_type, status_alerted);
  }

  target_type = alert->getHeaderField("target_type");
  target_value = alert->getHeaderField("target_value");

  if(target_type && target_value
     && !strncmp(target_type, "host", strlen("host"))) {
    if(StoreManager::iface)
      StoreManager::iface->hostStatusAlerted(target_value, alert_type, status_alerted);
  }
}

/* **************************************************** */

Alert* AlertsManager::getEngaged(Alert *alert) {
  u_int32_t hash;

  if(alert == NULL)
    return NULL;

  hash = alert->key() % num_hashes;

  if(table[hash] == NULL) {
    return NULL;
  } else {
    Alert *head;

    locks[hash]->lock(__FILE__, __LINE__);
    head = (Alert*)table[hash];

    while(head != NULL) {
      if(head->equal(alert))
	break;
      else
	head = (Alert*)head->next();
    }
    locks[hash]->unlock(__FILE__, __LINE__);

    return(head);
  }

}

/* **************************************************** */

bool AlertsManager::isEngaged(Alert *alert) {
  return(getEngaged(alert) != NULL);
}

/* **************************************************** */

bool AlertsManager::setEngaged(Alert *alert) {
  if(isEngaged(alert))
    return true;

  Alert *a = new Alert(*alert);

  if(!add(a))
    return false;
  else {
    incDecEngagedAlertsCounters(a, true /* counters++ */);
    updateStatusInformation(a, true /* alerted */);
    return true;
  }
}

/* **************************************************** */

bool AlertsManager::setReleased(Alert *alert) {
  Alert *a = getEngaged(alert);
  bool ret;

  if(!a) /* wasn't engaged */
    return true;

  /* Release can be triggered when the interface is 
     walking the hash so we must Lock */
  disablePurge();

  if(!remove(a))
    ret = false;
  else {
    incDecEngagedAlertsCounters(a, false /* counters-- */);
    updateStatusInformation(a, false /* no longer alerted */);
    delete a;
    ret = true;
  }

  enablePurge();

  return ret;
}

/* **************************************************** */

bool AlertsManager::setStored(Alert *alert) {
  /* Stored alerts don't go through the internal hash */
  if(!alert)
    return true;

  updateStatusInformation(alert, true /* alert sent */);

  return true;
}

/* **************************************************** */

void AlertsManager::startDequeueLoop() {
  pthread_create(&dequeueThreadLoop, NULL, ::dequeueLoop, (void*)this);
}

/* **************************************************** */

int AlertsManager::enqueue(const char *json_alert) {
  bool ret = false;
  if(!ntop->getPrefs()->are_alerts_disabled()) {
    producersMutex.lock(__FILE__, __LINE__);
    ret = alertsQueue->enqueue((void*)json_alert);
    producersMutex.unlock(__FILE__, __LINE__);
  }
  return ret ? 0 : -1;
}

/* **************************************************** */

AlertsManager::~AlertsManager() {
  if(alertsQueue) delete alertsQueue;
}

/* **************************************************** */

bool AlertsManager::initEngaged(Alert *a) {
  /* This method is public as it must be called from a static non-member
   callback. For this reason hash_initialized is used to prevent calls 
  from outside initEngaged() to have effect. */
  return hash_initialized || setEngaged(a);
}

/* **************************************************** */

static int init_engaged_alerts_callback(void *data, int argc, char **argv, char **azColName) {
  AlertsManager *am = (AlertsManager*)data;
  int json_index = 0; /* Make sure it's the first column in the select statement! */

  if(am) {
    Alert alert(argv[json_index]);
    /* Don't write to the db, just update the cache. The alert is, by definition,
     already in the db as this method is called from a db query. */
    am->initEngaged(&alert);
  }

  return 0;
}

/* **************************************************** */

int AlertsManager::initEngaged() {
  if(!ntop->getPrefs()->are_alerts_disabled()) {
    char query[STORE_MANAGER_MAX_QUERY];
    char *zErrMsg = 0;
    int rc = 0;

    if(!store_initialized || !store_opened)
      return -1;

    snprintf(query, sizeof(query),
	     "SELECT alert_json FROM %s "
	     "where is_engaged = 1 ; ",
	     ALERTS_MANAGER_TABLE);

    /* Do not lock here, make sure the method is called in the constructor */
    rc = sqlite3_exec(db, query, init_engaged_alerts_callback, (void*)this, &zErrMsg);

    if(rc != SQLITE_OK){
      rc = 1;
      ntop->getTrace()->traceEvent(TRACE_ERROR, "SQL Error: %s\n%s", zErrMsg, query);
      sqlite3_free(zErrMsg);
      goto out;
    }

    rc = 0;
    hash_initialized = true;
  out:

    return rc;
  } else
    return(-1);  
}

/* **************************************************** */

AlertsManager::AlertsManager(NetworkInterface *network_interface, const char *filename) : StoreManager(network_interface), GenericHash(network_interface, 1024, 4096) {
  char filePath[MAX_PATH], fileFullPath[MAX_PATH], fileName[MAX_PATH];

  snprintf(filePath, sizeof(filePath), "%s/%d/alerts/",
	   ntop->get_working_dir(), ifid);

  /* clean old databases */
  int base_offset = strlen(filePath);
  sprintf(&filePath[base_offset], "%s", "alerts.db");
  unlink(filePath);
  sprintf(&filePath[base_offset], "%s", "alerts_v2.db");
  unlink(filePath);
  filePath[base_offset] = 0;

  /* open the newest */
  strncpy(fileName, filename, sizeof(fileName));
  snprintf(fileFullPath, sizeof(fileFullPath), "%s/%d/alerts/%s",
	   ntop->get_working_dir(), ifid, filename);
  ntop->fixPath(filePath);
  ntop->fixPath(fileFullPath);

  if(!Utils::mkdir_tree(filePath)) {
    ntop->getTrace()->traceEvent(TRACE_WARNING,
				 "Unable to create directory %s", filePath);
    return;
  }

  store_initialized = init(fileFullPath) == 0 ? true : false;
  store_opened      = openStore()        == 0 ? true : false;
  make_room         = false;

  if(!store_initialized)
    ntop->getTrace()->traceEvent(TRACE_WARNING,
				 "Unable to initialize store %s",
				 fileFullPath);
  if(!store_opened)
    ntop->getTrace()->traceEvent(TRACE_WARNING,
				 "Unable to open store %s",
				 fileFullPath);

  snprintf(queue_name, sizeof(queue_name), ALERTS_MANAGER_QUEUE_NAME, ifid);

  if((alertsQueue = new SPSCQueue()) == NULL)
    throw "Not enough memory";

  hash_initialized = false; /* set to true by initEngaged */
  initEngaged();
}

/* **************************************************** */

int AlertsManager::openStore() {
  char create_query[STORE_MANAGER_MAX_QUERY * 3];
  int rc;

  if(!store_initialized)
    return 1;

  snprintf(create_query, sizeof(create_query),
	   "CREATE TABLE IF NOT EXISTS %s (        "
	   "alert_tstamp     INTEGER NOT NULL,     "
	   "alert_tstamp_end INTEGER DEFAULT NULL, "
	   "alert_type       TEXT NOT NULL,        "
	   "alert_severity   TEXT NOT NULL,        "
	   "source_type      TEXT DEFAULT NULL,    "
	   "source_value     TEXT DEFAULT NULL,    "
	   "target_type      TEXT DEFAULT NULL,    "
	   "target_value     TEXT DEFAULT NULL,    "
	   "alert_id         TEXT DEFAULT NULL,    "
	   "is_engaged       INTEGER DEFAULT 0,    "
	   "alert_json       TEXT DEFAULT NULL     "
	   ");"
	   "CREATE INDEX IF NOT EXISTS tai_tstamp   ON %s(alert_tstamp, alert_tstamp_end); "
	   "CREATE INDEX IF NOT EXISTS tai_tstamp_e ON %s(alert_tstamp_end); "
	   "CREATE INDEX IF NOT EXISTS tai_type     ON %s(alert_type); "
	   "CREATE INDEX IF NOT EXISTS tai_severity ON %s(alert_severity); "
	   "CREATE INDEX IF NOT EXISTS tai_origin   ON %s(source_type, source_value); "
	   "CREATE INDEX IF NOT EXISTS tai_target   ON %s(target_type, target_value); "
	   "CREATE INDEX IF NOT EXISTS tai_engaged  ON %s(source_type, source_value, target_type, target_value, alert_id, is_engaged); ",
	   ALERTS_MANAGER_TABLE, ALERTS_MANAGER_TABLE,
	   ALERTS_MANAGER_TABLE, ALERTS_MANAGER_TABLE, ALERTS_MANAGER_TABLE,
	   ALERTS_MANAGER_TABLE, ALERTS_MANAGER_TABLE, ALERTS_MANAGER_TABLE);
  m.lock(__FILE__, __LINE__);
  rc = exec_query(create_query, NULL, NULL);
  m.unlock(__FILE__, __LINE__);

  snprintf(create_query, sizeof(create_query),
	   "CREATE TABLE IF NOT EXISTS %s ("
	   "alert_tstamp     INTEGER NOT NULL, "
	   "alert_tstamp_end INTEGER DEFAULT NULL, "
	   "alert_type       INTEGER NOT NULL, "
	   "alert_severity   INTEGER NOT NULL, "
	   "alert_entity     INTEGER NOT NULL, "
	   "alert_entity_val TEXT NOT NULL,    "
	   "alert_origin     TEXT DEFAULT NULL,"
	   "alert_target     TEXT DEFAULT NULL,"
	   "alert_json       TEXT DEFAULT NULL "
	   "); "  // no need to create a primary key, sqlite has the rowid
	   "CREATE INDEX IF NOT EXISTS t1i_tstamp   ON %s(alert_tstamp); "
	   "CREATE INDEX IF NOT EXISTS t1i_tstamp_e ON %s(alert_tstamp_end); "
	   "CREATE INDEX IF NOT EXISTS t1i_type     ON %s(alert_type); "
	   "CREATE INDEX IF NOT EXISTS t1i_severity ON %s(alert_severity); "
	   "CREATE INDEX IF NOT EXISTS t1i_origin   ON %s(alert_origin); "
	   "CREATE INDEX IF NOT EXISTS t1i_target   ON %s(alert_target); "
	   "CREATE INDEX IF NOT EXISTS t1i_entity   ON %s(alert_entity, alert_entity_val); ",
	   ALERTS_MANAGER_TABLE_NAME, ALERTS_MANAGER_TABLE_NAME, ALERTS_MANAGER_TABLE_NAME,
	   ALERTS_MANAGER_TABLE_NAME, ALERTS_MANAGER_TABLE_NAME, ALERTS_MANAGER_TABLE_NAME,
	   ALERTS_MANAGER_TABLE_NAME, ALERTS_MANAGER_TABLE_NAME);
  m.lock(__FILE__, __LINE__);
  rc = exec_query(create_query, NULL, NULL);
  m.unlock(__FILE__, __LINE__);

  snprintf(create_query, sizeof(create_query),
	   "CREATE TABLE IF NOT EXISTS %s ("
	   "alert_id         TEXT NOT NULL, "
	   "alert_tstamp     INTEGER NOT NULL, "
	   "alert_type       INTEGER NOT NULL, "
	   "alert_severity   INTEGER NOT NULL, "
	   "alert_entity     INTEGER NOT NULL, "
	   "alert_entity_val TEXT NOT NULL,    "
	   "alert_origin     TEXT DEFAULT NULL,"
	   "alert_target     TEXT DEFAULT NULL,"
	   "alert_json       TEXT DEFAULT NULL "
	   ");"
	   "CREATE INDEX IF NOT EXISTS t2i_tstamp   ON %s(alert_tstamp); "
	   "CREATE INDEX IF NOT EXISTS t2i_type     ON %s(alert_type); "
	   "CREATE INDEX IF NOT EXISTS t2i_severity ON %s(alert_severity); "
	   "CREATE INDEX IF NOT EXISTS t2i_origin   ON %s(alert_origin); "
	   "CREATE INDEX IF NOT EXISTS t2i_target   ON %s(alert_target); "
	   "CREATE UNIQUE INDEX IF NOT EXISTS t2i_u ON %s(alert_entity, alert_entity_val, alert_id); ",
	   ALERTS_MANAGER_ENGAGED_TABLE_NAME, ALERTS_MANAGER_ENGAGED_TABLE_NAME, ALERTS_MANAGER_ENGAGED_TABLE_NAME,
	   ALERTS_MANAGER_ENGAGED_TABLE_NAME, ALERTS_MANAGER_ENGAGED_TABLE_NAME,
	   ALERTS_MANAGER_ENGAGED_TABLE_NAME, ALERTS_MANAGER_ENGAGED_TABLE_NAME);
  m.lock(__FILE__, __LINE__);
  rc = exec_query(create_query, NULL, NULL);
  m.unlock(__FILE__, __LINE__);

  snprintf(create_query, sizeof(create_query),
	   "CREATE TABLE IF NOT EXISTS %s ("
	   "alert_tstamp     INTEGER NOT NULL, "
	   "alert_type       INTEGER NOT NULL, "
	   "alert_severity   INTEGER NOT NULL, "
	   "alert_json       TEXT DEFAULT NULL, "
	   "vlan_id          INTEGER NOT NULL DEFAULT 0, "
	   "proto            INTEGER NOT NULL DEFAULT 0, "
	   "l7_proto         INTEGER NOT NULL DEFAULT %u, "
	   "first_switched   INTEGER NOT NULL DEFAULT 0, "
	   "last_switched    INTEGER NOT NULL DEFAULT 0, "
	   "cli_country      TEXT DEFAULT NULL, "
	   "srv_country      TEXT DEFAULT NULL, "
	   "cli_os           TEXT DEFAULT NULL, "
	   "srv_os           TEXT DEFAULT NULL, "
	   "cli_asn          TEXT DEFAULT NULL, "
	   "srv_asn          TEXT DEFAULT NULL, "
	   "cli_addr         TEXT DEFAULT NULL, "
	   "srv_addr         TEXT DEFAULT NULL, "
	   "cli_port         INTEGER NOT NULL DEFAULT 0, "
	   "srv_port         INTEGER NOT NULL DEFAULT 0, "
	   "cli2srv_bytes    INTEGER NOT NULL DEFAULT 0, "
	   "srv2cli_bytes    INTEGER NOT NULL DEFAULT 0, "
	   "cli2srv_packets  INTEGER NOT NULL DEFAULT 0, "
	   "srv2cli_packets  INTEGER NOT NULL DEFAULT 0, "
	   "cli2srv_tcpflags INTEGER DEFAULT NULL, "
	   "srv2cli_tcpflags INTEGER DEFAULT NULL, "
	   "cli_blacklisted  INTEGER NOT NULL DEFAULT 0, "
	   "srv_blacklisted  INTEGER NOT NULL DEFAULT 0, "
	   "cli_localhost    INTEGER NOT NULL DEFAULT 0, "
	   "srv_localhost    INTEGER NOT NULL DEFAULT 0 "
	   ");"
	   "CREATE INDEX IF NOT EXISTS t3i_tstamp    ON %s(alert_tstamp); "
	   "CREATE INDEX IF NOT EXISTS t3i_type      ON %s(alert_type); "
	   "CREATE INDEX IF NOT EXISTS t3i_severity  ON %s(alert_severity); "
	   "CREATE INDEX IF NOT EXISTS t3i_vlanid    ON %s(vlan_id); "
	   "CREATE INDEX IF NOT EXISTS t3i_proto     ON %s(proto); "
	   "CREATE INDEX IF NOT EXISTS t3i_l7proto   ON %s(l7_proto); "
	   "CREATE INDEX IF NOT EXISTS t3i_fswitched ON %s(first_switched); "
	   "CREATE INDEX IF NOT EXISTS t3i_lswitched ON %s(last_switched); "
	   "CREATE INDEX IF NOT EXISTS t3i_ccountry  ON %s(cli_country); "
	   "CREATE INDEX IF NOT EXISTS t3i_scountry  ON %s(srv_country); "
	   "CREATE INDEX IF NOT EXISTS t3i_cos       ON %s(cli_os); "
	   "CREATE INDEX IF NOT EXISTS t3i_sos       ON %s(srv_os); "
	   "CREATE INDEX IF NOT EXISTS t3i_casn      ON %s(cli_asn); "
	   "CREATE INDEX IF NOT EXISTS t3i_sasn      ON %s(srv_asn); "
	   "CREATE INDEX IF NOT EXISTS t3i_caddr     ON %s(cli_addr); "
	   "CREATE INDEX IF NOT EXISTS t3i_saddr     ON %s(srv_addr); "
	   "CREATE INDEX IF NOT EXISTS t3i_cport     ON %s(cli_port); "
	   "CREATE INDEX IF NOT EXISTS t3i_sport     ON %s(srv_port); "
	   "CREATE INDEX IF NOT EXISTS t3i_clocal    ON %s(cli_localhost); "
	   "CREATE INDEX IF NOT EXISTS t3i_slocal    ON %s(srv_localhost); ",
	   ALERTS_MANAGER_FLOWS_TABLE_NAME,
	   NDPI_PROTOCOL_UNKNOWN,
	   ALERTS_MANAGER_FLOWS_TABLE_NAME, ALERTS_MANAGER_FLOWS_TABLE_NAME,
	   ALERTS_MANAGER_FLOWS_TABLE_NAME, ALERTS_MANAGER_FLOWS_TABLE_NAME,
	   ALERTS_MANAGER_FLOWS_TABLE_NAME, ALERTS_MANAGER_FLOWS_TABLE_NAME,
	   ALERTS_MANAGER_FLOWS_TABLE_NAME, ALERTS_MANAGER_FLOWS_TABLE_NAME,
	   ALERTS_MANAGER_FLOWS_TABLE_NAME, ALERTS_MANAGER_FLOWS_TABLE_NAME,
	   ALERTS_MANAGER_FLOWS_TABLE_NAME, ALERTS_MANAGER_FLOWS_TABLE_NAME,
	   ALERTS_MANAGER_FLOWS_TABLE_NAME, ALERTS_MANAGER_FLOWS_TABLE_NAME,
	   ALERTS_MANAGER_FLOWS_TABLE_NAME, ALERTS_MANAGER_FLOWS_TABLE_NAME,
	   ALERTS_MANAGER_FLOWS_TABLE_NAME, ALERTS_MANAGER_FLOWS_TABLE_NAME,
	   ALERTS_MANAGER_FLOWS_TABLE_NAME, ALERTS_MANAGER_FLOWS_TABLE_NAME);
  m.lock(__FILE__, __LINE__);
  rc = exec_query(create_query, NULL, NULL);
  m.unlock(__FILE__, __LINE__);

  return rc;
}

/* **************************************************** */

bool AlertsManager::isAlertEngaged(AlertEntity alert_entity, const char *alert_entity_value, const char *engaged_alert_id) {
  char query[STORE_MANAGER_MAX_QUERY];
  sqlite3_stmt *stmt = NULL;
  int rc;
  bool found = false;

  snprintf(query, sizeof(query),
	   "SELECT 1 "
	   "FROM %s "
	   "WHERE alert_entity = ? AND alert_entity_val = ? AND alert_id = ? ",
	   ALERTS_MANAGER_ENGAGED_TABLE_NAME);

  m.lock(__FILE__, __LINE__);
  if(sqlite3_prepare(db, query, -1, &stmt, 0)) {
    ntop->getTrace()->traceEvent(TRACE_ERROR, "Unable to prepare statement for query %s.", query);
    goto out;
  } else if(sqlite3_bind_int(stmt,   1, static_cast<int>(alert_entity))
	    || sqlite3_bind_text(stmt,  2, alert_entity_value, -1, SQLITE_STATIC)
	    || sqlite3_bind_text(stmt,  3, engaged_alert_id, -1, SQLITE_STATIC)) {
    ntop->getTrace()->traceEvent(TRACE_ERROR, "Unable to bind values to prepared statement for query %s.", query);
    goto out;
  }

  while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
    if(rc == SQLITE_ROW) {
      found = true;
      // ntop->getTrace()->traceEvent(TRACE_NORMAL, "%s\n", sqlite3_column_text(stmt, 0));
    } else if(rc == SQLITE_ERROR) {
      ntop->getTrace()->traceEvent(TRACE_INFO, "SQL Error: step");
      rc = 1;
      goto out;
    }
  }

 out:
  if(stmt) sqlite3_finalize(stmt);
  m.unlock(__FILE__, __LINE__);

  return found;
}

/* **************************************************** */

void AlertsManager::markForMakeRoom(AlertEntity alert_entity, const char *alert_entity_value, const char *table_name) {
  if(!ntop->getPrefs()->are_alerts_disabled()) {
    Redis *r = ntop->getRedis();
    char k[128], buf[512];

    if(!r) {
      ntop->getTrace()->traceEvent(TRACE_ERROR, "Unable to get a valid Redis instances");
      return;
    }

    snprintf(k, sizeof(k), ALERTS_MANAGER_MAKE_ROOM_SET_NAME, ifid);

    snprintf(buf, sizeof(buf), "%i|%s|%s",
	     alert_entity,
	     alert_entity_value ? alert_entity_value : "",
	     table_name ? table_name : "");

    r->sadd(k, buf);
    make_room = true;
  }
}

/* **************************************************** */

// TODO remove table_name and rework makeRoom logic
void AlertsManager::makeRoom(AlertEntity alert_entity, const char *alert_entity_value, const char *table_name) {
  if(!ntop->getPrefs()->are_alerts_disabled() && make_room) {
    make_room = false;
    int max_num = strncmp(table_name, ALERTS_MANAGER_FLOWS_TABLE_NAME, strlen(ALERTS_MANAGER_FLOWS_TABLE_NAME))
      ? ntop->getPrefs()->get_max_num_alerts_per_entity() : ntop->getPrefs()->get_max_num_flow_alerts();
    int num = 0;
    ntop->getTrace()->traceEvent(TRACE_DEBUG, "Maximum configured number of alerts per entity: %i", max_num);

    if(max_num < 0)
      return; /* unlimited allowance */

    num = getNumAlerts("");

    ntop->getTrace()->traceEvent(TRACE_DEBUG, "Checking maximum %s for %s [got: %i]",
				 table_name ? table_name : (char*)"",
				 alert_entity_value ? alert_entity_value : (char*)"",
				 num);

    if(num >= max_num) {
      ntop->getTrace()->traceEvent(TRACE_DEBUG, "Maximum number of %s exceeded for %s",
				   table_name ? table_name : (char*)"",
				   alert_entity_value ? alert_entity_value : (char*)"");

      // TODO rework this logic
      //~ if(getNumAlerts(false /* too many alerts always go to not engaged table */,
		      //~ alert_entity, alert_entity_value,
		      //~ alert_too_many_alerts) > 0) {
	/* possibly delete the old too-many-alerts alert so that the new ones becomes the most recent */
	//~ deleteAlerts(false /* not engaged */, alert_entity, alert_entity_value, alert_too_many_alerts, 0);
      //~ }

      /* make room by deleting the oldest alert matching the input criteria */
      deleteOldestAlert(alert_entity, alert_entity_value, table_name, max_num - 1);

      char msg[256];
      snprintf(msg, sizeof(msg), "Too many %s alerts. Oldest alerts will be overwritten "
	       "unless you delete some alerts or increase their maximum number.",
	       alert_entity_value ? alert_entity_value : "");

      /* TODO migrate alert */
      //~ storeAlert(alert_entity, alert_entity_value,
		 //~ alert_too_many_alerts, alert_level_error, msg,
		 //~ NULL, NULL,
		 //~ false /* force store alert, do not check maximum here */);
    }
  }
}

/* **************************************************** */

int AlertsManager::deleteOldestAlert(AlertEntity alert_entity, const char *alert_entity_value,
				     const char *table_name, u_int32_t max_num_rows) {
  // TODO rework this logic
/*
  if(!ntop->getPrefs()->are_alerts_disabled()) {
    char query[STORE_MANAGER_MAX_QUERY];
    sqlite3_stmt *stmt = NULL;
    int rc = 0;
    bool flows_table = !strncmp(table_name, ALERTS_MANAGER_FLOWS_TABLE_NAME, strlen(ALERTS_MANAGER_FLOWS_TABLE_NAME));

    if(!store_initialized || !store_opened)
      return -1;

    snprintf(query, sizeof(query),
	     "DELETE FROM %s "
	     "WHERE rowid NOT IN "
	     "(SELECT rowid FROM %s "
	     "WHERE alert_type <> ? %s"
	     "ORDER BY alert_tstamp DESC LIMIT %u)",
	     table_name, table_name, !flows_table ? (char*)" AND alert_entity = ? AND alert_entity_val = ? " : (char*)"",
	     max_num_rows);

    ntop->getTrace()->traceEvent(TRACE_DEBUG, "Going to delete via: %s", query);

    m.lock(__FILE__, __LINE__);

    if(sqlite3_prepare(db, query, -1, &stmt, 0)
       || sqlite3_bind_int(stmt,   1, static_cast<int>(alert_entity))
       || (!flows_table && sqlite3_bind_text(stmt,  2, alert_entity_value, -1, SQLITE_STATIC))
       || (!flows_table && sqlite3_bind_int(stmt,   3, static_cast<int>(alert_too_many_alerts)))) {
      rc = 1;
      goto out;
    }

    while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
      if(rc == SQLITE_ERROR) {
	ntop->getTrace()->traceEvent(TRACE_INFO, "SQL Error: step");
	rc = 1;
	goto out;
      }
    }

    rc = 0;
  out:
    if(stmt) sqlite3_finalize(stmt);
    m.unlock(__FILE__, __LINE__);

    return rc; }*/
   return(0);
}

/* **************************************************** */

SlackNotificationChoice AlertsManager::getSlackNotificationChoice(char* choice) {
  if(strcmp(choice, "only_errors") == 0)         return notify_errors_only;
  if(strcmp(choice, "errors_and_warnings") == 0) return notify_errors_and_warnings;

  return notify_all_alerts; /* default choice */
}

/* **************************************************** */

#ifdef NOT_USED
void AlertsManager::notifyAlert(AlertEntity alert_entity, const char *alert_entity_value,
				const char *engaged_alert_id,
				AlertType alert_type, AlertLevel alert_severity,
				const char *alert_json,
				const char *alert_origin, const char *alert_target) {
  if(!ntop->getPrefs()->are_alerts_disabled()) {
    json_object *notification;
    char alert_sender_name[64], message[2015], notification_username[96];
    const char *json_alert, *level;

    if((notification = json_object_new_object()) == NULL) return;

    json_object_object_add(notification, "channel",
			   json_object_new_string(getAlertEntity(alert_entity)));
    json_object_object_add(notification, "icon_emoji",
			   json_object_new_string(getAlertLevel(alert_severity)));

    if(ntop->getRedis()->get((char*)ALERTS_MANAGER_SENDER_USERNAME,
			     alert_sender_name, sizeof(alert_sender_name)) >= 0) {
      switch(alert_severity) {
      case alert_level_error:   level = "ERROR";   break;
      case alert_level_warning: level = "WARNING"; break;
      case alert_level_info:    level = "INFO";    break;
      }

      snprintf(notification_username, sizeof(notification_username),
	       "%s [%s]", alert_sender_name, level);

      json_object_object_add(notification, "username",
			     json_object_new_string(notification_username));
    }

    snprintf(message, sizeof(message), "%s [%s][%s][Origin: %s][Target: %s]",
	     getAlertType(alert_type),
	     alert_entity_value ? alert_entity_value : "",
	     engaged_alert_id ? engaged_alert_id : "",
	     alert_origin ? alert_origin : "",
	     alert_target ? alert_target : "");
    json_object_object_add(notification, "text", json_object_new_string(message));

    json_alert = json_object_to_json_string(notification);

    if(ntop->getRedis()->lpush(ALERTS_MANAGER_NOTIFICATION_QUEUE_NAME,
			       (char*)json_alert, ALERTS_MANAGER_MAX_ENTITY_ALERTS) < 0)
      ntop->getTrace()->traceEvent(TRACE_WARNING,
				   "An error occurred when pushing alert %s to redis list %s.",
				   json_alert, ALERTS_MANAGER_NOTIFICATION_QUEUE_NAME);

    /* Free memory */
    json_object_put(notification);
  }
}
#endif

/* **************************************************** */

/*void AlertsManager::notifySlack(AlertEntity alert_entity, const char *alert_entity_value,
				const char *engaged_alert_id,
				AlertType alert_type, AlertLevel alert_severity,
				const char *alert_json,
				const char *alert_origin, const char *alert_target) {
  if(!ntop->getPrefs()->are_alerts_disabled()) {
    char choice[32];
    bool alert_to_be_notified = false;
    SlackNotificationChoice notification_choice;

    if(ntop->getPrefs()->are_notifications_enabled()) {
      ntop->getRedis()->get((char*) ALERTS_MANAGER_NOTIFICATION_SEVERITY, choice, sizeof(choice));

      notification_choice = getSlackNotificationChoice(choice);

      if(notification_choice == notify_all_alerts)
	alert_to_be_notified=true;
      else if(notification_choice == notify_errors_and_warnings) {
	if((alert_severity == alert_level_error) || (alert_severity == alert_level_warning))
	  alert_to_be_notified = true;
      } else {
	if((notification_choice == notify_errors_only) && (alert_severity == alert_level_error))
	  alert_to_be_notified = true;
      }

      if(alert_to_be_notified)
	notifyAlert(alert_entity, alert_entity_value, engaged_alert_id,
		    alert_type, alert_severity, alert_json,
		    alert_origin, alert_target);
    }
  }
}*/

/* ******************************************* */

bool AlertsManager::isValidHost(Host *h, char *host_string, size_t host_string_len) {
  char ipbuf[256];

  if(!h) return false;

  IpAddress *ip = h->get_ip();
  if(!ip) return false;

  snprintf(host_string, host_string_len, "%s@%i", ip->print(ipbuf, sizeof(ipbuf)), h->get_vlan_id());

  return true;
}

/* ******************************************* */

struct alertsRetriever {
  lua_State *vm;
  u_int32_t current_offset;
};

static int getAlertsCallback(void *data, int argc, char **argv, char **azColName){
  alertsRetriever *ar = (alertsRetriever*)data;
  lua_State *vm = ar->vm;

  lua_newtable(vm);

  for(int i = 0; i < argc; i++){
    lua_push_str_table_entry(vm, azColName[i], argv[i]);
  }

  lua_pushnumber(vm, ++ar->current_offset);
  lua_insert(vm, -2);
  lua_settable(vm, -3);

  return 0;
}

/* **************************************************** */

int AlertsManager::getNumAlerts(const char *sql_where_clause) {
  if(!ntop->getPrefs()->are_alerts_disabled()) {
    char query[STORE_MANAGER_MAX_QUERY];
    sqlite3_stmt *stmt = NULL;
    int rc;
    int num = -1;

    snprintf(query, sizeof(query),
	     "SELECT count(*) "
	     "FROM %s "
	     "%s %s",
	     ALERTS_MANAGER_TABLE,
	     sql_where_clause ? "WHERE"  : "",
	     sql_where_clause ? sql_where_clause : "");

    //  ntop->getTrace()->traceEvent(TRACE_NORMAL, "Going to execute: %s", query);

    m.lock(__FILE__, __LINE__);
    if(sqlite3_prepare(db, query, -1, &stmt, 0)) {
      ntop->getTrace()->traceEvent(TRACE_ERROR, "Unable to prepare statement for query %s.", query);
      goto out;
    }

    while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
      if(rc == SQLITE_ROW) {
	num = sqlite3_column_int(stmt, 0);
	// ntop->getTrace()->traceEvent(TRACE_NORMAL, "%s\n", sqlite3_column_text(stmt, 0));
      } else if(rc == SQLITE_ERROR) {
	ntop->getTrace()->traceEvent(TRACE_INFO, "SQL Error: step");
	goto out;
      }
    }

  out:
    if(stmt) sqlite3_finalize(stmt);
    m.unlock(__FILE__, __LINE__);

    return num;
  } else
    return(0);
}

/* **************************************************** */

/*int AlertsManager::deleteAlerts(bool engaged, AlertEntity alert_entity,
				const char *alert_entity_value, AlertType alert_type, time_t older_than) {
  if(!ntop->getPrefs()->are_alerts_disabled()) {
    char query[STORE_MANAGER_MAX_QUERY];
    sqlite3_stmt *stmt = NULL;
    int rc;

    snprintf(query, sizeof(query),
	     "DELETE FROM %s WHERE alert_entity = ? AND alert_entity_val = ? AND alert_type = ?",
	     engaged ? ALERTS_MANAGER_ENGAGED_TABLE_NAME : ALERTS_MANAGER_TABLE_NAME);

    if(older_than>0)
      sqlite3_snprintf(sizeof(query) - strlen(query) - 1,
		       &query[strlen(query)],
		       " AND alert_tstamp < %lu", older_than);

    m.lock(__FILE__, __LINE__);
    if(sqlite3_prepare(db, query, -1, &stmt, 0)
       || sqlite3_bind_int(stmt,   1, static_cast<int>(alert_entity))
       || sqlite3_bind_text(stmt,  2, alert_entity_value, -1, SQLITE_STATIC)
       || sqlite3_bind_int(stmt,   3, static_cast<int>(alert_type))) {
      ntop->getTrace()->traceEvent(TRACE_ERROR, "Unable to prepare statement for query %s.", query);
      rc = -1;
      goto out;
    }

    while((rc = sqlite3_step(stmt)) != SQLITE_DONE) {
      if(rc == SQLITE_ERROR) {
	ntop->getTrace()->traceEvent(TRACE_INFO, "SQL Error: step");
	rc = -2;
	goto out;
      }
    }

    rc = 0;
  out:
    if(stmt) sqlite3_finalize(stmt);
    m.unlock(__FILE__, __LINE__);

    return rc;
  } else
    return(0);
}*/

/* ******************************************* */

int AlertsManager::queryAlertsRaw(lua_State *vm, const char *selection,
				  const char *clauses) {
  const char *table_name = "alerts";

  if(!ntop->getPrefs()->are_alerts_disabled()) {
    alertsRetriever ar;
    char query[STORE_MANAGER_MAX_QUERY];
    char *zErrMsg = NULL;
    int rc;

    snprintf(query, sizeof(query),
	     "%s FROM %s %s ",
	     selection ? selection : "SELECT *",
	     table_name,
	     clauses ? clauses : (char*)"");

    // ntop->getTrace()->traceEvent(TRACE_NORMAL, "Going to execute: %s", query);

    m.lock(__FILE__, __LINE__);

    lua_newtable(vm);

    ar.vm = vm, ar.current_offset = 0;
    rc = sqlite3_exec(db, query, getAlertsCallback, (void*)&ar, &zErrMsg);

    if( rc != SQLITE_OK ){
      rc = 1;
      ntop->getTrace()->traceEvent(TRACE_ERROR, "SQL Error: %s\n%s", zErrMsg, query);
      sqlite3_free(zErrMsg);
      goto out;
    }

    rc = 0;
  out:
    m.unlock(__FILE__, __LINE__);

    return rc;
  } else
    return(0);
}

/* ******************************************* */
