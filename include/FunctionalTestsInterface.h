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

#include "ntop_includes.h"

class FunctionalTestsInterface : public PcapInterface {
 private:
  char test_script_name[MAX_PATH];
  pthread_t testsAfterPoll;

  char *scriptName(char *buf, size_t buf_size);

 public:
  FunctionalTestsInterface(const char *name);
  ~FunctionalTestsInterface();

  inline const char* get_type()       { return(CONST_INTERFACE_TYPE_F_TESTS); };
  inline char* get_test_script_name() { return(test_script_name); };

  void runTest();
  void startPacketPolling();
  void startTestsAfterPolling();
};
