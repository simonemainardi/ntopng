--
-- (C) 2020 - ntop.org
--

require "lua_utils"
local json = require "dkjson"

local elasticsearch = {}

elasticsearch.EXPORT_FREQUENCY = 60
elasticsearch.API_VERSION = "0.2"
elasticsearch.REQUEST_TIMEOUT = 1
elasticsearch.ITERATION_TIMEOUT = 3
elasticsearch.prio = 400
local MAX_ALERTS_PER_REQUEST = 10

-- ##############################################

function elasticsearch.isAvailable()
   -- Currently, this endpoint is available only
   -- if ntopng has been started with -F "es;"
   local conn = ntop.elasticsearchConnection()

   return conn
end

-- ##############################################

function elasticsearch.sendMessage(alerts)
   local url = ntop.getPref("ntopng.prefs.alerts.elasticsearch_url")
   local sharedsecret = ntop.getPref("ntopng.prefs.alerts.elasticsearch_sharedsecret")
   local username = ntop.getPref("ntopng.prefs.alerts.elasticsearch_username")
   local password = ntop.getPref("ntopng.prefs.alerts.elasticsearch_password")

   if isEmptyString(url) then
      return false
   end

   local message = {
      version = elasticsearch.API_VERSION,
      sharedsecret = sharedsecret,
      alerts = alerts,
   }

   local json_message = json.encode(message)

   local rc = false
   local retry_attempts = 3
   while retry_attempts > 0 do
      if ntop.postHTTPJsonData(username, password, url, json_message, elasticsearch.REQUEST_TIMEOUT) then
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

      if diff >= elasticsearch.ITERATION_TIMEOUT then
	 break
      end

      local json_alert = ntop.lpopCache(queue)

      if not json_alert then
	 break
      end

      local alert = json.decode(json_alert)

      table.insert(alerts, alert)

      if #alerts >= MAX_ALERTS_PER_REQUEST then
	 if not elasticsearch.sendMessage(alerts) then
	    ntop.delCache(queue)
	    return {success=false, error_message="Unable to send alerts to the elasticsearch"}
	 end
	 alerts = {}
      end
   end

   if #alerts > 0 then
      if not elasticsearch.sendMessage(alerts) then
	 ntop.delCache(queue)
	 return {success=false, error_message="Unable to send alerts to the elasticsearch"}
      end
   end

   return {success=true}
end

-- ##############################################

function elasticsearch.handlePost()
   local message_info, message_severity

   if(_POST["send_test_elasticsearch"] ~= nil) then
      local success = elasticsearch.sendMessage({})

      if success then
	 message_info = i18n("prefs.elasticsearch_sent_successfully")
	 message_severity = "alert-success"
      else
	 message_info = i18n("prefs.elasticsearch_send_error", {product=product})
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

   -- print('<tr id="elasticsearch_test" style="' .. ternary(showElasticsearchNotificationPrefs, "", "display:none;").. '"><td><button class="btn btn-secondary disable-on-dirty" type="button" onclick="sendTestElasticsearch();" style="width:230px; float:left;">'..i18n("prefs.send_test_elasticsearch")..'</button></td></tr>')

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

