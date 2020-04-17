--
-- (C) 2020 - ntop.org
--

require "lua_utils"
local json = require "dkjson"
local alert_consts = require "alert_consts"

-- ##############################################

local elasticsearch = {}

-- ##############################################

elasticsearch.EXPORT_FREQUENCY = 60
elasticsearch.API_VERSION = "0.1"
elasticsearch.prio = 400

-- ##############################################

local ITERATION_TIMEOUT = 15
local REQUEST_TIMEOUT = 3
local MAX_ALERTS_PER_REQUEST = 128
local INDEX_NAME = "ntopng-alerts"

-- ##############################################

function elasticsearch.isAvailable()
   -- Currently, this endpoint is available only
   -- if ntopng has been started with -F "es;"
   local conn = ntop.elasticsearchConnection()

   return conn
end

-- ##############################################

local function formatCommonPart(alert_json)
   local res = {}

   -- Add a @timestamp which is compatible and friendly with elasticsearch
   --
   -- The `!` at the beginning of the date string format: this is to tell the time is UTC.
   -- Elasticsearch will adjust the UTC time according to the client time.
   --
   -- Alerts should always have an `alert_tstamp`, but in case they don't have it, `now` is chosen as @timestamp
   res["@timestamp"] = os.date("!%Y-%m-%dT%H:%M:%S.0Z", alert_json["alert_tstamp"] or now)

   res["alert_tstamp"] = alert_json["alert_tstamp"]
   res["alert_tstamp_end"] = alert_json["alert_tstamp_end"]
   res["alert_type"] = alert_consts.alertTypeRaw(alert_json["alert_type"])
   res["alert_severity"] = alert_consts.alertSeverityRaw(alert_json["alert_severity"])
   res["alert_entity"] = alert_consts.alertEntityRaw(alert_json["alert_entity"])
   res["alert_entity_val"] = alert_json["alert_entity_val"]
   res["ifid"] = alert_json["ifid"]
   res["if_name"] = getInterfaceName(alert_json["ifid"])
   res["instance_name"] = ntop.getInstanceName()

   tprint(res)
   return res
end

-- ##############################################

local function formatFlowAlert(alert_json)
   local res = formatCommonPart(alert_json)

   return res
end

-- ##############################################

local function formatAlert(alert_json)
   local res = formatCommonPart(alert_json)

   return res
end

-- ##############################################

local function format(alert_json)
   if alert_json["is_flow_alert"] then
      return formatFlowAlert(alert_json)
   else
      return formatAlert(alert_json)
   end
end

-- ##############################################
-- @brief
local function sendMessage(alerts)
   local conn = ntop.elasticsearchConnection()
   local now = os.time()

   if isEmptyString(conn.url) then
      -- No url is known, cannot export
      return false
   end

   if not alerts or #alerts == 0 then
      -- Nothing to do
      return true
   end

   -- The header requested by _bulk API
   -- https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
   local header = {
      index = {
	 _type = nil, -- Elasticsearch 7.0 complains with "Specifying types in bulk requests is deprecated" -- "_doc",
	 _index = INDEX_NAME
      }
   }
   local header_json = json.encode(header)

   -- Build the payload
   local payload_table = {}
   for _, alert in ipairs(alerts) do
      local alert_json = json.decode(alert)

      if alert_json then
	 -- Each alert must have the header repeated
	 payload_table[#payload_table + 1] = header_json
	 payload_table[#payload_table + 1] = json.encode(format(alert_json))
      end
   end

   if #payload_table == 0 then
      -- Nothing to do
      return true
   end

   -- Elasticsearch _bulk API wants a newline-delimited JSON (NDJSON)
   -- Must also contains a newline at the end
   local payload = table.concat(payload_table, "\n").."\n"

   local rc = false
   local retry_attempts = 3
   while retry_attempts > 0 do
      if ntop.postHTTPJsonData(conn.user or '', conn.password or '', conn.url, payload, REQUEST_TIMEOUT) then
	 rc = true
	 break
      end
      retry_attempts = retry_attempts - 1
   end

   return rc
end

-- ##############################################

function elasticsearch.dequeueAlerts(queue)
   local start_time = os.time()

   local alerts = {}

   while true do
      local diff = os.time() - start_time

      if diff >= ITERATION_TIMEOUT then
	 break
      end

      local alerts = ntop.lrangeCache(queue, 0, MAX_ALERTS_PER_REQUEST - 1)

      if not alerts or #alerts == 0 then
	 break
      end

      if not sendMessage(alerts) then
	 return {
	    success = false,
	    error_message = i18n("prefs.elasticsearch_unable_to_send_alerts"),
	 }
      end

      -- Remove processed messages from the queue
      ntop.ltrimCache(queue, #alerts, -1)
   end

   return {success = true}
end

-- ##############################################

-- @brief Callback triggered when the user clicks test connection on the alert endpoint page
--        this function peforms a GET to the Elasticsearch host and make sure the connection is working
function elasticsearch.handlePost()
   local message_info, message_severity = '', ''
   local conn = ntop.elasticsearchConnection()

   if _POST["send_test_elasticsearch"] then
      -- GET the base host which returns version number
      sendMessage({json.encode({alert_id = 1}),json.encode({alert_id = 2}),json.encode({alert_id = 3})})
      local res = ntop.httpGet(conn.host, conn.user, conn.password, REQUEST_TIMEOUT, true)

      if res and res["RESPONSE_CODE"] == 200 then
	 message_info = i18n("prefs.elasticsearch_sent_successfully")
	 message_severity = "alert-success"
      else
	 message_info = i18n("prefs.elasticsearch_send_error", {
				code = res and res["RESPONSE_CODE"] or 0,
				resp = res and res["CONTENT"] or ""})
	 message_severity = "alert-danger"
      end
   end

   return message_info, message_severity
end

-- ##############################################

function elasticsearch.printPrefs(alert_endpoints, subpage_active, showElements)
   print('<thead class="thead-light"><tr><th colspan="2" class="info">'..i18n("prefs.elasticsearch_notification")..'</th></tr></thead>')

   local elementToSwitchElasticsearch = {"row_elasticsearch_notification_severity_preference", "elasticsearch_url", "elasticsearch_sharedsecret", "elasticsearch_test", "elasticsearch_username", "elasticsearch_password"}

   prefsToggleButton(subpage_active, {
			field = "toggle_elasticsearch_notification",
			pref = alert_endpoints.getAlertNotificationModuleEnableKey("elasticsearch", true),
			default = "0",
			disabled = showElements==false,
			to_switch = elementToSwitchElasticsearch,
   })


   local showElasticsearchNotificationPrefs = false
   if ntop.getPref(alert_endpoints.getAlertNotificationModuleEnableKey("elasticsearch")) == "1" then
      showElasticsearchNotificationPrefs = true
   else
      showElasticsearchNotificationPrefs = false
   end

   print('<tr id="elasticsearch_test" style="' .. ternary(showElasticsearchNotificationPrefs, "", "display:none;").. '"><td><button class="btn btn-secondary disable-on-dirty" type="button" onclick="sendTestElasticsearch();" style="width:230px; float:left;">'..i18n("prefs.send_test_elasticsearch")..'</button></td></tr>')

   print[[<script>
  function sendTestElasticsearch() {
    var params = {};

    params.send_test_elasticsearch = "";
    params.csrf = "]] print(ntop.getRandomCSRFValue()) print[[";

    var form = paramsToForm('<form method="post"></form>', params);
    form.appendTo('body').submit();
  }
</script>]]
end

-- ##############################################

return elasticsearch

