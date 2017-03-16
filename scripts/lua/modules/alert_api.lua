--
-- (C) 2014-17 - ntop.org
--

require 'lua_utils'
require 'class_utils'

InterfaceAlert = class(Alert, function(c, ifid)
			  Alert.init(c, 'interface', ifid, nil, nil, alert_type)
end)

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
