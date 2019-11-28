--
-- (C) 2013-18 - ntop.org
--

local dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path
if((dirs.scriptdir ~= nil) and (dirs.scriptdir ~= "")) then package.path = dirs.scriptdir .. "/lua/modules/?.lua;" .. package.path end
require "lua_utils"
local alerts_api = require("alerts_api")
local recording_utils = require "recording_utils"
local remote_assistance = require "remote_assistance"
local telemetry_utils = require "telemetry_utils"
local ts_utils = require("ts_utils_core")

local is_admin = isAdministrator()

print[[
<script>
   /* Some localization strings to pass from lua to javacript */
   var i18n = {
      "no_results_found": "]] print(i18n("no_results_found")) print[[",
      "change_number_of_rows": "]] print(i18n("change_number_of_rows")) print[[",
      "no_data_available": "]] print(i18n("no_data_available")) print[[",
      "showing_x_to_y_rows": "]] print(i18n("showing_x_to_y_rows", {x="{0}", y="{1}", tot="{2}"})) print[[",
      "actions": "]] print(i18n("actions")) print[[",
      "query_was_aborted": "]] print(i18n("graphs.query_was_aborted")) print[[",
      "exports": "]] print(i18n("system_stats.exports_label")) print[[",
   };

   var http_prefix = "]] print(ntop.getHttpPrefix()) print[[";
</script>]]

if ntop.isnEdge() then
   dofile(dirs.installdir .. "/pro/scripts/lua/nedge/inc/menu.lua")
   return
end

local template = require "template_utils"

prefs = ntop.getPrefs()
local iface_names = interface.getIfNames()

-- tprint(iface_names)

num_ifaces = 0
for k,v in pairs(iface_names) do
   num_ifaces = num_ifaces+1
end

print [[
    <nav class="mnb navbar navbar-default navbar-fixed-top">
      <div class="container-fluid">

        <!-- Sidebar Toggle Button -->
        <div class="navbar-header">
          <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
            <span class="sr-only">Toggle navigation</span>
            <i class="ic fa fa-bars"></i>
          </button>
          <div style="padding: 15px 0;">
            <a href="#" id="msbo"><i class="ic fa fa-bars"></i></a>
          </div>
        </div>

        <!-- Top Menu -->
        <div id="navbar" class="navbar-collapse collapse">
          <ul class="nav navbar-nav navbar-right">
]]

interface.select(ifname)
local ifs = interface.getStats()
local is_pcap_dump = interface.isPcapDumpInterface()
local is_packet_interface = interface.isPacketInterface()
ifId = ifs.id

-- ##############################################
-- Interfaces Selector

print [[
      <li class="dropdown">
        <a class="dropdown-toggle" role="button" data-toggle="dropdown" href="#" aria-haspopup="true" aria-expanded="false">]] print(ifname) print[[</a>
        <ul class="dropdown-menu">
]]

local views = {}
local drops = {}
local recording = {}
local packetinterfaces = {}
local ifnames = {}
local ifdescr = {}
local ifHdescr = {}
local ifCustom = {}
local dynamic = {}

for v,k in pairs(iface_names) do
   interface.select(k)
   local _ifstats = interface.getStats()
   ifnames[_ifstats.id] = k
   ifdescr[_ifstats.id] = _ifstats.description
   --io.write("["..k.."/"..v.."][".._ifstats.id.."] "..ifnames[_ifstats.id].."=".._ifstats.id.."\n")
   if(_ifstats.isView == true) then views[k] = true end
   if(_ifstats.isDynamic == true) then dynamic[k] = true end
   if(recording_utils.isEnabled(_ifstats.id)) then recording[k] = true end
   if(interface.isPacketInterface()) then packetinterfaces[k] = true end
   if(_ifstats.stats_since_reset.drops * 100 > _ifstats.stats_since_reset.packets) then
      drops[k] = true
   end
   ifHdescr[_ifstats.id] = getHumanReadableInterfaceName(_ifstats.description.."")
   ifCustom[_ifstats.id] = _ifstats.customIftype
end

-- First round: only physical interfaces
-- Second round: only virtual interfaces

for round = 1, 2 do

   for k,_ in pairsByValues(ifHdescr, asc) do
      local descr
      
      if((round == 1) and (ifCustom[k] ~= nil)) then
   	 -- do nothing
      elseif((round == 2) and (ifCustom[k] == nil)) then
      	 -- do nothing
      else
	 v = ifnames[k]

         local page_params = table.clone(_GET)
         page_params.ifid = k
         -- ntop.getHttpPrefix()
         local url = getPageUrl("", page_params)

         print("<li>")
	 if(v == ifname) then
	    print("<a class=\"dropdown-item\" href=\""..url.."\">")
	 else
	    print[[<form id="switch_interface_form_]] print(tostring(k)) print[[" method="post" action="]] print(url) print[[">]]
	    print[[<input name="switch_interface" type="hidden" value="1" />]]
	    print[[<input name="csrf" type="hidden" value="]] print(ntop.getRandomCSRFValue()) print[[" />]]
	    print[[</form>]]
	    print[[<a class="dropdown-item" href="javascript:void(0);" onclick="$('#switch_interface_form_]] print(tostring(k)) print[[').submit();">]]
	 end

	 if(v == ifname) then print("<i class=\"fa fa-check\"></i> ") end
	 if(isPausedInterface(v)) then  print('<i class="fa fa-pause"></i> ') end

	 descr = getHumanReadableInterfaceName(v.."")

	 if(string.contains(descr, "{")) then -- Windows
	    descr = ifdescr[k]      
	 else
	    if(v ~= ifdescr[k]) then
	       descr = descr .. " (".. ifdescr[k] ..")"
	    end
	 end

	 print(descr)

	 if(views[v] == true) then
	    print(' <i class="fa fa-eye" aria-hidden="true"></i> ')
	 end

	 if(dynamic[v] == true) then
	    print(' <i class="fa fa-code-fork" aria-hidden="true"></i> ')
	 end

	 if(drops[v] == true) then
	    print('&nbsp;<span><i class="fa fa-tint" aria-hidden="true"></i></span>')
	 end

	 if(recording[v] == true) then
	    print(' <i class="fa fa-hdd-o" aria-hidden="true"></i> ')
	 end

	 print("</a>")
         print("</li>")
      end
   end
end

print [[
      </ul>
    </li>
]]

-- ##############################################
-- Logout

if(_SESSION["user"] ~= nil and _SESSION["user"] ~= ntop.getNologinUser()) then
print [[
    <li class="dropdown">
      <a class="nav-link dropdown-toggle" href="#" id="navbarLogout" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
         <i class="fa fa-sm fa-sign-out"></i>
      </a>
      <ul class="dropdown-menu">
        <li><a class="dropdown-item" href="]] print(ntop.getHttpPrefix()) print [[/lua/logout.lua"><i class="fa fa-sign-out"></i> ]] print(i18n("login.logout_user_x", {user=_SESSION["user"]})) print [[</a></li>
      </ul>
    </li>
]]
end

if(not is_admin) then
   dofile(dirs.installdir .. "/scripts/lua/inc/password_dialog.lua")
end

-- ##############################################
-- Search

print(
  template.gen("typeahead_input.html", {
    typeahead={
      base_id     = "host_search",
      action      = "", -- see makeFindHostBeforeSubmitCallback
      json_key    = "ip",
      query_field = "host",
      class       = "navbar-form navbar-right typeahead-dropdown-right",
      query_url   = ntop.getHttpPrefix() .. "/lua/find_host.lua",
      query_title = i18n("search_host"),
      style       = "width:16em;",
      before_submit = [[makeFindHostBeforeSubmitCallback("]] .. ntop.getHttpPrefix() .. [[")]],
      max_items   = "'all'" --[[ let source script decide ]],
    }
  })
)

print [[
</ul>
]]

print [[
        </div>
      </div>
    </nav>
]]

-- Sidebar

print [[
    <div class="msb" id="msb">
      <nav class="navbar navbar-default" role="navigation">

        <!-- Logo -->
        <div class="navbar-header">
          <div class="brand-wrapper">
            <div class="brand-name-wrapper">
              <a class="navbar-brand" href="]] print(ntop.getHttpPrefix() .. "/") print [[">]] addLogoSvg() print [[</a>
            </div>
          </div>
        </div>

        <div class="side-menu-container">
          <!--ul class="nav navbar-nav"-->
          <ul class="list-unstyled components">
]]

-- ##############################################
-- Dashboard

if not is_pcap_dump then
   if(active_page == "dashboard") then
      print [[ <li class="active"> ]]
   else
      print [[ <li class=""> ]]
   end
   print [[
            <a href="#dashboardSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">
              <i class="fa fa-dashboard fa-lg"></i> <b class="caret"></b>
            </a>
            <ul class="collapse list-unstyled" id="dashboardSubmenu">
              <li><a href="]]
print(ntop.getHttpPrefix())
if ntop.isPro() then
   print("/lua/pro/dashboard.lua")
else
   print("/lua/index.lua")
end
print [["><i class="fa fa-dashboard"></i> ]] print(i18n("dashboard.traffic_dashboard")) print[[</a></li>]]

if(interface.isDiscoverableInterface()) then
   print('<li><a href="'..ntop.getHttpPrefix()..'/lua/discover.lua"><i class="fa fa-lightbulb-o"></i> ') print(i18n("prefs.network_discovery")) print('</a></li>')
end

if(ntop.isPro()) then
  print('<li><a href="'..ntop.getHttpPrefix()..'/lua/pro/report.lua"><i class="fa fa-area-chart"></i> ') print(i18n("report.traffic_report")) print('</a></li>')
end

if ntop.isPro() and prefs.is_dump_flows_to_mysql_enabled and not ifs.isViewed then
  print('<li class="divider"></li>')
  print('<li><a href="'..ntop.getHttpPrefix()..'/lua/pro/db_explorer.lua?ifid='..ifId..'"><i class="fa fa-history"></i> ') print(i18n("db_explorer.historical_data_explorer")) print('</a></li>')
end

print [[
            </ul>
          </li>
   ]]
end

-- ##############################################
-- Flows

url = ntop.getHttpPrefix().."/lua/flows_stats.lua"

if(active_page == "flows") then
   print('<li class="active"><a href="'..url..'">') print(i18n("flows")) print('</a></li>')
else
   print('<li><a href="'..url..'">') print(i18n("flows")) print('</a></li>')
end

-- ##############################################
-- Hosts

if not ifs.isViewed then -- Currently, hosts are not kept for viewed interfaces, only for their view
   if active_page == "hosts" then
      print [[ <li class="active"> ]]
   else
      print [[ <li class=""> ]]
   end
print [[ 
            <a href="#hostsSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">
              ]] print(i18n("flows_page.hosts")) print[[ <b class="caret"></b>
            </a>
            <ul class="collapse list-unstyled" id="hostsSubmenu">
      <li><a href="]]
print(ntop.getHttpPrefix())
print [[/lua/hosts_stats.lua">]] print(i18n("flows_page.hosts")) print[[</a></li>
      ]]


if ifs["has_macs"] == true then
   print('<li><a href="'..ntop.getHttpPrefix()..'/lua/macs_stats.lua?devices_mode=source_macs_only">') print(i18n("users.devices")) print('</a></li>')
end

print('<li><a href="'..ntop.getHttpPrefix()..'/lua/network_stats.lua">') print(i18n("networks")) print('</a></li>')

print('<li><a href="'..ntop.getHttpPrefix()..'/lua/pool_stats.lua">') print(i18n("host_pools.host_pools")) print('</a></li>')

if(ntop.hasGeoIP()) then
   print('<li><a href="'..ntop.getHttpPrefix()..'/lua/as_stats.lua">') print(i18n("prefs.toggle_asn_rrds_title")) print('</a></li>')
   print('<li><a href="'..ntop.getHttpPrefix()..'/lua/country_stats.lua">') print(i18n("countries")) print('</a></li>')
end
print('<li><a href="'..ntop.getHttpPrefix()..'/lua/os_stats.lua">') print(i18n("operating_systems")) print('</a></li>')

if(interface.hasVLANs()) then
   print('<li><a href="'..ntop.getHttpPrefix()..'/lua/vlan_stats.lua">') print(i18n("vlan_stats.vlans")) print('</a></li>')
end

if ifs.has_seen_pods then
   print('<li><a href="'..ntop.getHttpPrefix()..'/lua/pods_stats.lua">') print(i18n("containers_stats.pods")) print('</a></li>')
end
if ifs.has_seen_containers then
   print('<li><a href="'..ntop.getHttpPrefix()..'/lua/containers_stats.lua">') print(i18n("containers_stats.containers")) print('</a></li>')
end

print('<li class="divider"></li>')
print('<li class="dropdown-header">') print(i18n("local_traffic")) print('</li>')

print('<li><a href="'..ntop.getHttpPrefix()..'/lua/http_servers_stats.lua">') print(i18n("http_servers_stats.http_servers")) print('</a></li>')

if not is_pcap_dump then
   print('<li><a href="'..ntop.getHttpPrefix()..'/lua/top_hosts.lua"><i class="fa fa-trophy"></i> ') print(i18n("processes_stats.top_hosts")) print('</a></li>')
end

print('<li class="divider"></li>')

if(not(isLoopback(ifname))) then
   print [[
	    <li><a href="]]
print(ntop.getHttpPrefix())
print [[/lua/hosts_geomap.lua"><i class="fa fa-map-marker"></i> ]] print(i18n("geo_map.geo_map")) print[[</a></li>]]

   print[[<li><a href="]] print(ntop.getHttpPrefix())
   print [[/lua/hosts_treemap.lua"><i class="fa fa-sitemap"></i> ]] print(i18n("tree_map.hosts_treemap")) print[[</a></li>]]
end

if(ntop.getPrefs().is_arp_matrix_generation_enabled) then
   print('<li><a href="'..ntop.getHttpPrefix()..'/lua/arp_matrix_graph.lua"><i class="fa fa-th-large"></i> ') print(i18n("arp_top_talkers")) print('</a></li>')
end

print [[
      <li><a href="]]
print(ntop.getHttpPrefix())
print [[/lua/bubble.lua"><i class="fa fa-circle-o"></i> Host Explorer</a></li>
   ]]

print("</ul> </li>")

end -- closes not ifs.isViewed

-- Exporters
local info = ntop.getInfo()

if((ifs["type"] == "zmq") and ntop.isEnterprise()) then
  if active_page == "exporters" then
    print [[ <li class="active"> ]]
  else
    print [[ <li class=""> ]]
  end
  print [[ 
            <a href="#exportersSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">
              ]] print(i18n("flow_devices.exporters")) print[[ <b class="caret"></b>
            </a>
            <ul class="collapse list-unstyled" id="exportersSubmenu">
]]

   local has_ebpf_events, has_sflow_devs = false, false
   if ifs.has_seen_ebpf_events then
      has_ebpf_events = true
      print('<li><a href="'..ntop.getHttpPrefix()..'/lua/pro/enterprise/event_exporters.lua ">') print(i18n("event_exporters.event_exporters")) print('</a></li>')
   elseif table.len(interface.getSFlowDevices() or {}) > 0 then
      has_sflow_devs = true
      print('<li><a href="'..ntop.getHttpPrefix()..'/lua/pro/enterprise/flowdevices_stats.lua?sflow_filter=All">') print(i18n("flows_page.sflow_devices")) print('</a></li>')

   end

   if has_ebpf_events or has_sflow_devs then
      print('<li class="divider"></li>')
      print('<li class="dropdown-header">') print(i18n("flows")) print('</li>')
   end

   print('<li><a href="'..ntop.getHttpPrefix()..'/lua/pro/enterprise/flowdevices_stats.lua">') print(i18n("flows_page.flow_exporters")) print('</a></li>')

  print [[

      </ul>
    </li>]]
end

-- ##############################################
-- Interface

if(num_ifaces > 0) then

   url = ntop.getHttpPrefix().."/lua/if_stats.lua"

   if(active_page == "if_stats") then
      print('<li class="active"><a href="'..url..'">') print(i18n("interface")) print('</a></li>')
   else
      print('<li><a href="'..url..'">') print(i18n("interface")) print('</a></li>')
   end

end -- num_ifaces

-- ##############################################
-- System

if isAllowedSystemInterface() then
   local system_scripts = require("system_scripts_utils")

  if active_page == "system_stats" or active_page == "system_interfaces_stats" then
    print [[ <li class="active"> ]]
  else
    print [[ <li class=""> ]]
  end
  print [[ 
            <a href="#systemSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">
              ]] print(i18n("system")) print[[ <b class="caret"></b>
            </a>
            <ul class="collapse list-unstyled" id="systemSubmenu">
]]

   if ntop.isEnterprise() then
      print('<li><a href="'..ntop.getHttpPrefix()..'/lua/pro/enterprise/snmpdevices_stats.lua">') print(i18n("prefs.snmp")) print('</a></li>')
   end

   print[[<li><a href="]] print(ntop.getHttpPrefix()) print[[/lua/system_stats.lua">]] print(i18n("system_status")) print[[</a></li>]]

   if num_ifaces > 1 then
      print[[<li><a href="]] print(ntop.getHttpPrefix()) print[[/lua/system_interfaces_stats.lua">]] print(i18n("system_interfaces_status")) print[[</a></li>]]
   end

   local system_menu_entries = system_scripts.getSystemMenuEntries()

   if #system_menu_entries > 0 then
      print('<li class="divider"></li>')
      print('<li class="dropdown-header">') print(i18n("system_stats.probes")) print('</li>')

      for _, entry in ipairs(system_scripts.getSystemMenuEntries()) do
	 print[[<li><a href="]] print(entry.url) print[[">]] print(entry.label) print[[</a></li>]]
      end
   end

   print[[</ul>]]
end

-- ##############################################
-- Alerts

if ntop.getPrefs().are_alerts_enabled == true then
   local active = ""
   local style = ""
   local color = ""

   -- if alert_cache["num_alerts_engaged"] > 0 then
   -- color = 'style="color: #B94A48;"' -- bootstrap danger red
   -- end

   if not ifs["has_alerts"] and not alerts_api.hasEntitiesWithAlertsDisabled(ifId) then
      style = ' style="display: none;"'
   end

   if active_page == "alerts" then
      active = ' active'
   end

   -- local color = "#F0AD4E" -- bootstrap warning orange
   print [[
      <li class="]] print(active) print[[" id="alerts-id"]] print(style) print[[>
        <a href="#alertsSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">
	  <i class="fa fa-warning fa-lg "]] print(color) print[["></i> <b class="caret"></b>
        </a>
        <ul class="collapse list-unstyled" id="alertsSubmenu">
          <li>
            <a  href="]]
   print(ntop.getHttpPrefix())
   print [[/lua/show_alerts.lua">
              <i class="fa fa-warning" id="alerts-menu-triangle"></i> ]] print(i18n("show_alerts.detected_alerts")) print[[
            </a>
          </li>
]]
   if ntop.isEnterprise() then
      print[[
      <li>
        <a href="]]
      print(ntop.getHttpPrefix())
      print[[/lua/pro/enterprise/alerts_dashboard.lua"><i class="fa fa-dashboard"></i> ]] print(i18n("alerts_dashboard.alerts_dashboard")) print[[
        </a>
     </li>
     <li class="divider"></li>
     <li><a href="]] print(ntop.getHttpPrefix())
      print[[/lua/pro/enterprise/flow_alerts_explorer.lua"><i class="fa fa-history"></i> ]] print(i18n("flow_alerts_explorer.label")) print[[
        </a>
     </li>
]]
   end

   print[[
    </ul>
  </li>
   ]]
end

-- ##############################################
-- Admin

  if active_page == "admin" then
    print [[ <li class="active"> ]]
  else
    print [[ <li class=""> ]]
  end
  print [[ 
            <a href="#adminSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">
              <i class="fa fa-cog fa-lg"></i> <b class="caret"></b>
            </a>
            <ul class="collapse list-unstyled" id="adminSubmenu">
]]

if _SESSION["localuser"] then
   if(is_admin) then
     print[[<li><a href="]] print(ntop.getHttpPrefix())
     print[[/lua/admin/users.lua"><i class="fa fa-user"></i> ]] print(i18n("manage_users.manage_users")) print[[</a></li>]]
   else
     print [[<li><a href="#password_dialog"  data-toggle="modal"><i class="fa fa-user"></i> ]] print(i18n("login.change_password")) print[[</a></li>]]
   end
end

if(is_admin) then
   print("<li><a href=\""..ntop.getHttpPrefix().."/lua/admin/prefs.lua\"><i class=\"fa fa-flask\"></i> ") print(i18n("prefs.preferences")) print("</a></li>\n")

   if remote_assistance.isAvailable() then
      print("<li><a href=\""..ntop.getHttpPrefix().."/lua/admin/remote_assistance.lua\"><i class=\"fa fa-commenting\"></i> ") print(i18n("remote_assistance.remote_assistance")) print("</a></li>\n")
   end

   if(ntop.isPro()) then
      print("<li><a href=\""..ntop.getHttpPrefix().."/lua/pro/admin/edit_profiles.lua\"><i class=\"fa fa-user-md\"></i> ") print(i18n("traffic_profiles.traffic_profiles")) print("</a></li>\n")
      if(false) then
	 print("<li><a href=\""..ntop.getHttpPrefix().."/lua/pro/admin/list_reports.lua\"><i class=\"fa fa-archive\"></i> Reports Archive</a></li>\n")
      end
   end

   print("<li><a href=\""..ntop.getHttpPrefix().."/lua/admin/edit_categories.lua\"><i class=\"fa fa-tags\"></i> ") print(i18n("custom_categories.apps_and_categories")) print("</a></li>\n")
   print("<li><a href=\""..ntop.getHttpPrefix().."/lua/admin/edit_category_lists.lua\"><i class=\"fa fa-sticky-note\"></i> ") print(i18n("category_lists.category_lists")) print("</a></li>\n")


   print("<li><a href=\""..ntop.getHttpPrefix().."/lua/admin/edit_device_protocols.lua\"><i class=\"fa fa-tablet\"></i> ") print(i18n("device_protocols.device_protocols")) print("</a></li>\n")
end

if _SESSION["localuser"] or is_admin then
   print [[
      <li class="divider"></li>]]
end

print [[
      <li><a href="]]
print(ntop.getHttpPrefix())
print [[/lua/manage_data.lua"><i class="fa fa-hdd-o"></i> ]] print(i18n("manage_data.manage_data")) print[[</a></li>]]

if(is_admin) then
  print [[
      <li><a href="]]
  print(ntop.getHttpPrefix())
  print [[/lua/get_config.lua"><i class="fa fa-download"></i> ]] print(i18n("conf_backup.conf_backup")) print[[</a></li>]]

  print[[ <li><a href="https://www.ntop.org/guides/ntopng/web_gui/settings.html#restore-configuration" target="_blank"><i class="fa fa-upload"></i> ]] print(i18n("conf_backup.conf_restore")) print[[ <i class="fa fa-external-link"></i></a></li>]]
end

print[[
    </ul>
  </li>]]

-- ##############################################
-- Info

if active_page == "home" or active_page == "about" or active_page == "telemetry" or active_page == "directories" then
    print [[ <li class="active"> ]]
  else
    print [[ <li class=""> ]]
  end
  print [[ 
      <a href="#aboutSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">
        <i class="fa fa-info-circle fa-lg"></i> <b class="caret"></b>
      </a>
      <ul class="collapse list-unstyled" id="aboutSubmenu">
      <li><a href="]] print(ntop.getHttpPrefix()) print [[/lua/about.lua"><i class="fa fa-question-circle"></i> ]] print(i18n("about.about_ntopng")) print[[</a></li>
      <li><a href="]] print(ntop.getHttpPrefix()) print[[/lua/telemetry.lua"><i class="fa fa-rss"></i> ]] print(i18n("telemetry")) print[[</a></li>
      <li><a href="http://blog.ntop.org/" target="_blank"><i class="fa fa-bullhorn"></i> ]] print(i18n("about.ntop_blog")) print[[ <i class="fa fa-external-link"></i></a></li>
      <li><a href="https://t.me/ntop_community" target="_blank"><i class="fa fa-telegram"></i> ]] print(i18n("about.telegram")) print[[ <i class="fa fa-external-link"></i></a></li>
      <li><a href="https://github.com/ntop/ntopng/issues" target="_blank"><i class="fa fa-bug"></i> ]] print(i18n("about.report_issue")) print[[ <i class="fa fa-external-link"></i></a></li>

      <li class="divider"></li>
      <li><a href="]] print(ntop.getHttpPrefix()) print [[/lua/directories.lua"><i class="fa fa-folder"></i> ]] print(i18n("about.directories")) print[[</a></li>
      <li><a href="]] print(ntop.getHttpPrefix()) print[[/lua/user_scripts_overview.lua"><i class="fa fa-superpowers"></i> ]] print(i18n("about.user_scripts")) print[[</a></li>
      <li><a href="]] print(ntop.getHttpPrefix()) print[[/lua/defs_overview.lua"><i class="fa fa-warning"></i> ]] print(i18n("about.alert_defines")) print[[</a></li>
      <li><a href="https://www.ntop.org/guides/ntopng/" target="_blank"><i class="fa fa-book"></i> ]] print(i18n("about.readme_and_manual")) print[[ <i class="fa fa-external-link"></i></a></li>
      <li><a href="https://www.ntop.org/guides/ntopng/api/" target="_blank"><i class="fa fa-book"></i> ]] print("Lua/C API") print[[ <i class="fa fa-external-link"></i></a></li>
    </ul>
]]

-- ##############################################
-- End Of Sidebar

print [[
          </ul>
        </div>
      </nav>
    </div>

    <script id="rendered-js">
      (function () {
        $('#msbo').on('click', function () {
          $('body').toggleClass('msb-x');
        });
      })();
    </script>

    <div class="mcw" id="content">
]]

-- ##############################################
-- Content

-- select the original interface back to prevent possible issues
interface.select(ifname)

if(dirs.workingdir == "/var/tmp/ntopng") then
   print('<br><div class="alert alert-danger" role="alert"><i class="fa fa-warning fa-lg" id="alerts-menu-triangle"></i> <A HREF="https://www.ntop.org/support/faq/migrate-the-data-directory-in-ntopng/">')
   print(i18n("about.datadir_warning"))
   print('</a></div>')
end

local lbd_serialize_by_mac = (_POST["lbd_hosts_as_macs"] == "1") or (ntop.getPref(string.format("ntopng.prefs.ifid_%u.serialize_local_broadcast_hosts_as_macs", ifs.id)) == "1")

if(ifs.has_seen_dhcp_addresses and is_admin and (not is_pcap_dump) and is_packet_interface) then
   if(not lbd_serialize_by_mac) then
      if(ntop.getPref(string.format("ntopng.prefs.ifid_%u.disable_host_identifier_message", ifs.id)) ~= "1") then
         print('<br><div id="host-id-message-warning" class="alert alert-warning" role="alert"><i class="fa fa-warning fa-lg" id="alerts-menu-triangle"></i> ')
         print[[<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>]]
         print(i18n("about.host_identifier_warning", {name=i18n("prefs.toggle_host_tskey_title"), url = ntop.getHttpPrefix().."/lua/if_stats.lua?page=config"}))
         print('</a></div>')
      end
   elseif isEmptyString(_POST["dhcp_ranges"]) then
      local dhcp_utils = require("dhcp_utils")
      local ranges = dhcp_utils.listRanges(ifs.id)

      if(table.empty(ranges)) then
         print('<br><div class="alert alert-warning" role="alert"><i class="fa fa-warning fa-lg" id="alerts-menu-triangle"></i> ')
         print(i18n("about.dhcp_range_missing_warning", {
            name = i18n("prefs.toggle_host_tskey_title"),
            url = ntop.getHttpPrefix().."/lua/if_stats.lua?page=config",
            dhcp_url = ntop.getHttpPrefix().."/lua/if_stats.lua?page=dhcp"}))
         print('</a></div>')
      end
   end
end

-- Hidden by default, will be shown by the footer if necessary
print('<div id="influxdb-error-msg" class="alert alert-danger" style="display:none" role="alert"><i class="fa fa-warning fa-lg" id="alerts-menu-triangle"></i> <span id="influxdb-error-msg-text"></span>')
print[[<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>]]
print('</div>')

-- Hidden by default, will be shown by the footer if necessary
print('<div id="move-rrd-to-influxdb" class="alert alert-warning" style="display:none" role="alert"><i class="fa fa-warning fa-lg" id="alerts-menu-triangle"></i> ')
print[[<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>]]
print(i18n("about.influxdb_migration_msg", {url="https://www.ntop.org/ntopng/ntopng-and-time-series-from-rrd-to-influxdb-new-charts-with-time-shift/"}))
print('</div>')

if(_SESSION["INVALID_CSRF"]) then
  print('<div id="move-rrd-to-influxdb" class="alert alert-warning" role="alert"><i class="fa fa-warning fa-lg" id="alerts-menu-triangle"></i> ')
  print[[<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>]]
  print(i18n("expired_csrf"))
  print('</div>')
end

telemetry_utils.show_notice()
