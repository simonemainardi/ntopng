--
-- (C) 2013-16 - ntop.org
--

dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path

if (ntop.isPro()) then
  package.path = dirs.installdir .. "/pro/scripts/callbacks/?.lua;" .. package.path
end

require "lua_utils"

local ifstats   = interface.getStats()
local flowsinfo = interface.getFlowsInfo()

assert(ifstats.stats.bytes == 240)
assert(flowsinfo.numFlows == 1)

assert(flowsinfo.flows[0] == nil)
assert(flowsinfo.flows[2] == nil)
local flow = flowsinfo.flows[1]

assert(flow["cli.ip"] == "192.168.2.130")
assert(flow["srv.ip"] == "8.8.8.8")
