--
-- (C) 2013-17 - ntop.org
--

dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path

require "lua_utils"
require "alert_utils"
local json = require "dkjson"

sendHTTPHeader('text/html; charset=iso-8859-1')

if tonumber(_GET["row_id"]) ~= nil then
   local res = interface.queryAlertsRaw("select alert_json", "where rowid=".._GET["row_id"])

   if (res ~= nil) and (res[1] ~= nil) then
      res = res[1].alert_json
   end

   print(res)
   return
end

status          = _GET["status"]

engaged = false
if status == "engaged" then
   engaged = true
end

interface.select(ifname)

if(tonumber(_GET["currentPage"]) == nil) then _GET["currentPage"] = 1 end
if(tonumber(_GET["perPage"]) == nil) then _GET["perPage"] = getDefaultTableSize() end

if(isEmptyString(_GET["sortColumn"]) or (_GET["sortColumn"] == "column_")) then
   _GET["sortColumn"] = getDefaultTableSort("alerts")
elseif((_GET["sortColumn"] ~= "column_") and (_GET["sortColumn"] ~= "")) then
   tablePreferences("sort_alerts", _GET["sortColumn"])
end

if _GET["sortOrder"] == nil then
   _GET["sortOrder"] = getDefaultTableSortOrder("alerts")
elseif((_GET["sortColumn"] == "column_") or (_GET["sortOrder"] == "")) then
   _GET["sortOrder"] = "asc"
end
tablePreferences("sort_order_alerts", _GET["sortOrder"])

local alert_options = _GET

local num_alerts = tonumber(_GET["totalRows"])
if num_alerts == nil then
   num_alerts = getNumAlerts(status, alert_options)
end

local alerts = getAlerts(status, alert_options)
local res = {}

res["currentPage"] = alert_options.currentPage
res["data"] = {}

if alerts == nil then alerts = {} end

for _key,_value in ipairs(alerts) do
   local row = {}

   alert_id        = _value["rowid"]
   if _value["alert_entity"] ~= nil then
      row["column_entity"]    = alertEntityLabel(_value["alert_entity"])
   else
      row["column_entity"]    = "flow" -- flow alerts page doesn't have an entity
   end

   if _value["alert_entity_val"] ~= nil then
      row["column_entity_val"] = _value["alert_entity_val"]
   else
      row["column_entity_val"] = ""
   end
--   tprint(alert_entity)
   --   tprint(alert_entity_val)
   local tdiff = os.time()-_value["alert_tstamp"]

   if(tdiff < 3600) then
      row["column_date"]  = secondsToTime(tdiff).." ago"
   else
      row["column_date"] = os.date("%c", _value["alert_tstamp"])
   end

   row["column_duration"] = "-"
   if engaged == true then
      row["column_duration"] = secondsToTime(os.time() - tonumber(_value["alert_tstamp"]))
   elseif tonumber(_value["alert_tstamp_end"]) ~= nil then
      row["column_duration"] = secondsToTime(tonumber(_value["alert_tstamp_end"]) - tonumber(_value["alert_tstamp"]))
   end

   row["column_severity"] = alertSeverityLabel(_value["alert_severity"])
   row["column_type"]     = alertTypeLabel(_value["alert_type"])
   local alert_message = _value["alert_json"] or "{}"

   if ((string.len(alert_message) > 0) and (string.sub(alert_message, 1, 1)) == "{") then
      -- this is JSON
      local alert_json = json.decode(alert_message, 1)
      row["column_msg"] = (formatAlertMessage(alert_json) or alert_message).. " [<a href='"..ntop.getHttpPrefix().."/lua/get_alerts_data.lua?row_id=".._value["rowid"].."'>json</a>]"
   else
      row["column_msg"] = string.gsub(alert_json, '"', "'")
   end

   column_id = ""

   if not engaged then
      column_id = "<form class=form-inline style='display:inline; margin-bottom: 0px;' method='post'>"
      column_id = column_id.."<input type=hidden name='id_to_delete' value='"..alert_id.."'><button class='btn btn-default btn-xs' type='submit'><input id=csrf name=csrf type=hidden value='"..ntop.getRandomCSRFValue().."' /><i type='submit' class='fa fa-trash-o'></i></button></form>"
   end

   if ntop.isEnterprise() and (status == "historical") then
      local explore = function()
	 local url = ntop.getHttpPrefix() .. "/lua/pro/enterprise/flow_alerts_explorer.lua?"
	 local origin = _value["cli_addr"]
	 local target = _value["srv_addr"]
	 if origin ~= nil and origin ~= "" then
	    url = url..'&origin='..origin
	 end
	 if target ~= nil and target ~= "" then
	    url = url..'&target='..target
	 end
	 if _value["alert_tstamp"] ~= nil then
	    url = url..'&epoch_begin='..(tonumber(_value["alert_tstamp"]) - 1800)
	    url = url..'&epoch_end='..(tonumber(_value["alert_tstamp"]) + 1800)
	 end
	 return "&nbsp;<a class='btn btn-default btn-xs' href='"..url.."' title='"..i18n("flow_alerts_explorer.label").."'><i class='fa fa-history'></i><sup><i class='fa fa-exclamation-triangle' aria-hidden='true' style='position:absolute; margin-left:-19px; margin-top:4px;'></i></sup></a>&nbsp;"
      end
      column_id = column_id.." "..explore()
   end
   row["column_key"] = column_id

   if not isEmptyString(_value["source_type"]) then
      row["column_source"] = formatEntity(_value["source_type"], _value["source_value"], true)
   else
      row["column_source"] = "-"
   end
   if not isEmptyString(_value["target_type"]) then
      row["column_target"] = formatEntity(_value["target_type"], _value["target_value"], true)
   else
      row["column_target"] = "-"
   end
   
   res["data"][#res["data"] + 1] = row
end -- for

res["perPage"] = alert_options.perPage
res["sort"] = {{alert_options.sortColumn, alert_options.sortOrder}}
res["totalRows"] = num_alerts

print(json.encode(res))

