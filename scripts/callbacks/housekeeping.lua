--
-- (C) 2013-17 - ntop.org
--
-- This script is used to perform activities that are low
-- priority with respect to second.lua but that require
-- near realtime execution.
-- This script is executed every few seconds (default 3)
--

dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path

require "lua_utils"
require "alert_utils"
require "slack_utils"
local callback_utils = require "callback_utils"

housekeepingAlertsMakeRoom()
sendSlackMessages()

local ifnames = interface.getIfNames()

callback_utils.foreachInterface(ifnames, false, function(ifname, ifstats)
  processAnomalousFlows()
end)

interface.select("en4")
processAnomalousHosts()

