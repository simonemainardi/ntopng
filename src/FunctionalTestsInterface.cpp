/*
 *
 * (C) 2013-16 - ntop.org
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

#ifndef _FUNCTIONAL_TESTS_INTERFACE_H_
#define _FUNCTIONAL_TESTS_INTERFACE_H_

#include "ntop_includes.h"

/* **************************************************** */

FunctionalTestsInterface::FunctionalTestsInterface(const char *name) : PcapInterface(name) {
  scriptName(test_script_name, sizeof(test_script_name));
  // TODO: check that actually name is a pcap file
}

/* **************************************************** */

FunctionalTestsInterface::~FunctionalTestsInterface() {
  // TODO: implement destructor
}

/* **************************************************** */

char *FunctionalTestsInterface::scriptName(char *buf, size_t buf_size) {
  if(buf == NULL)
    return NULL;

  char *basename;
  if((basename = strrchr(get_name(),
			       '/' /* TODO: deal with windows separators */)) == NULL)
    basename = get_name();
  
  snprintf(buf, buf_size, "%s/%s.test.lua", CONST_DEFAULT_TESTS_LUA_DIR, basename);
  ntop->fixPath(buf);
  return buf;
}

/* **************************************************** */

void FunctionalTestsInterface::runTest() {
  struct stat statbuf;
  char *path = get_test_script_name();

  if(stat(path, &statbuf)) {
    ntop->getTrace()->traceEvent(TRACE_ERROR, "Missing script %s", path);
    return;
  }

  Lua *l;
  if((l = new(std::nothrow) Lua()) == NULL) {
    ntop->getTrace()->traceEvent(TRACE_WARNING,
				 "Unable to create test Lua VM");
    return;
  }
  ntop->getTrace()->traceEvent(TRACE_INFO, "Starting test %s", path);
  l->run_script(path);
  ntop->getTrace()->traceEvent(TRACE_INFO, "Test %s done.", path);
  delete l;
}

/* **************************************************** */

static void* testsAfterPollLoop(void* ptr) {
  FunctionalTestsInterface *iface = (FunctionalTestsInterface*)ptr;
  ntop->getTrace()->traceEvent(TRACE_NORMAL, "Functional tests for: %s", iface->get_name());

  iface->runTest();

  return NULL;
}

/* **************************************************** */

void FunctionalTestsInterface::startPacketPolling() {
  PcapInterface::startPacketPolling(); /* business as usual.. */

  /* waiting for the termination of the poll loop thread body */
  pthread_join(pollLoop, NULL);
  ntop->getTrace()->traceEvent(TRACE_NORMAL, "Poll loop completed, starting functional test...");

  /* the poll loop body has terminated so now it is time to run the tests */
  pthread_create(&testsAfterPoll, NULL, testsAfterPollLoop, (void*)this);
  pthread_join(testsAfterPoll, NULL);

  /* signal ourselves that the test is done so ntopng can begin the 
   teardown procedures */
  raise(SIGTERM);
}

#endif /* _FUNCTIONAL_TESTS_INTERFACE_H_ */
