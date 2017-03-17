--
-- (C) 2014-17 - ntop.org
--

require 'lua_utils'
require 'class_utils'
local json = require('dkjson')

Alert = class(function(al, source_type, source_value, target_type, target_value)
      al.header = {
	 source_type = source_type,
	 source_value = source_value,
	 target_type = target_type,
	 target_value = target_value,
	 alert_type = 'generic',
	 alert_severity = 'unknown',
	 alert_id = nil,
	 timestamp = os.time()
      }
end)

function Alert:engage(alert_id)
   self.header.status = 'engaged'
   if alert_id then
      self.header.alert_id = alert_id
   end
end

function Alert:release(alert_id)
   self.header.status = 'released'
   if alert_id then
      self.header.alert_id = alert_id
   end
end

function Alert:addFlow(f)
   if f.dump() then
      self.flow_detail = f.dump()
   end
end

function Alert:typeThresholdCross(time_granularity, metric, actual_value, operator, threshold)
   self.header.alert_type = 'threshold_cross'
   self.header.alert_severity = 'warning'
   self.header.alert_id = time_granularity..'_'..metric
   self.alert_detail = {time_granularity=time_granularity,
			metric=metric}
   if threshold ~= nil then self.alert_detail.threshold = threshold end
   if operator ~= nil then self.alert_detail.operator = operator end
   if actual_value ~= nil then self.alert_detail.actual_value = actual_value end
end

function Alert:typeMalwareSiteAccess(host_server_name)
   self.header.alert_type = 'malware_access'
   self.header.alert_severity = 'error'
   self.alert_detail = {host_server_name=host_server_name}
end

function Alert:__tostring()
   return json.encode(self)
end

--------------------------------------------------------------------------------

InterfaceAlert = class(Alert, function(c, ifname)
			  Alert.init(c, 'interface', ifname, nil, nil, alert_type)
end)

--------------------------------------------------------------------------------

HostAlert = class(Alert, function(c, hostkey)
		     local hostinfo = interface.getHostInfo(hostkey, nil, false, false)
		     local src = hostkey

		     if not isEmptyString(src) then
			src = src:gsub('@0', '')
		     end

		     -- JSON for the source detail
		     if hostinfo ~= nil and type(hostinfo) == "table" then
			c.source_detail = hostinfo
		     end

		     Alert.init(c, 'host', src, nil, nil)
end)

--------------------------------------------------------------------------------

NetworkAlert = class(Alert, function(c, network_name)
			  Alert.init(c, 'network', network_name, nil, nil, alert_type)
			  -- TODO network_name is optional, retrieve it if not provided
end)

--------------------------------------------------------------------------------

FlowAlert = class(Alert, function(c, source_host, source_vlan, dst_host, dst_vlan)
		     local src = hostinfo2hostkey({host=source_host, vlan=source_vlan})
		     local dst = hostinfo2hostkey({host=dst_host, vlan=dst_vlan})
		     Alert.init(c, 'host', src, 'host', dst, alert_type)
end)

--[[

EXAMPLES

require 'alert_utils'
require 'alert_api'

local nn = os.time()

ia = InterfaceAlert(1)
ia:typeThresholdCross('minute', 'bytes', 10, '>', 20)
-- tprint(tostring(ia))

ha = HostAlert('192.168.2.0', 1)
ha:typeThresholdCross('hour', 'packets', 500, '<', 30)
ha2 = HostAlert('10.0.0.0', 0)
ha2:typeThresholdCross('minute', 'bytes', 500, '<', 30)
-- tprint(tostring(ha))

fa = FlowAlert('192.168.2.1', 1, '192.168.2.2', 1)
fa:typeMalwareSiteAccess('www.abadyguy.com')
interface.alert(tostring(fa))
-- tprint(tostring(fa))

if nn % 10 == 0 then
   print("engaging!")

   ia:engage()
   interface.alert(tostring(ia))


   ha:engage()
   interface.alert(tostring(ha))

   ha2:engage()
   interface.alert(tostring(ha2))

elseif nn % 10 == 5 then
   print("releasing!")

   ia:release()
   interface.alert(tostring(ia))

   ha:release()
   interface.alert(tostring(ha))

   ha2:release()
   interface.alert(tostring(ha2))
end

--]]
