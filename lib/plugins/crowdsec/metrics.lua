-- expected
-- {
--   "remediation_components": [
--     {
--       "version": "string",
--       "meta": {
--         "window_size_seconds": 0,
--         "utc_startup_timestamp": 0,
--         "utc_now_timestamp": 0
--       },
--       "os": {
--         "name": "string",
--         "version": "string"
--       },
--       "metrics": [
--         {
--           "name": "string",
--           "value": 0,
--           "unit": "string",
--           "labels": {
--             "additionalProp1": "string",
--             "additionalProp2": "string",
--             "additionalProp3": "string"
--           }
--         }
--       ],
--       "feature_flags": [
--         "string"
--       ],
--       "type": "string",
--       "name": "string",
--       "last_pull": 0
--     }
--   ]
-- }

local cjson = require "cjson"
local http = require "resty.http"

local metrics = {}

metrics.__index = metrics
metrics.cache = ngx.shared.crowdsec_cache


-- Constructor for the store
function metrics:new(userAgent, window, startup_timestamp)
  self.cache:set("metrics_data", cjson.encode({
    version = userAgent,
    meta = {
      window_size_seconds = window,
      utc_startup_timestamp = startup_timestamp,
    },
    os = {
      name = "",
      version = ""
    }
  }))
end

-- Increment the value of a key or initialize it if it does not exist
function metrics:increment(key, increment)
    increment = increment or 1

    local value, err, forcible = self.cache:incr("metrics" .. key, increment, 0)
    if err then
        ngx.log(ngx.ERR, "failed to increment key: ", err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    return value
end

-- Export the store data to JSON
function metrics:toJson()
  local metrics_array = {}
  local metrics_data = self.cache:get("metrics_data")
  ngx.log(ngx.INFO, "metrics_data: " .. metrics_data)
  local keys = {"CAPI","LAPI","cscli","unknown"}
  for key in ipairs(keys) do
    local cache_key = "metrics" .. key
    table.insert(metrics_array, {
      name = key,
      value = self.cache:get(cache_key),
      unit = "number of requests",
    })
  end
  return cjson.encode({metrics_data, metrics_array})
end

function metrics:sendMetrics(link, headers, ssl)
  local body = self:toJson()
  ngx.log(ngx.INFO, "Sending metrics to " .. link .. "/v1/usage-metrics")
  ngx.log(ngx.INFO, "metrics: " .. body)
  local httpc = http.new()
  local res, err = httpc:request_uri(link .. "/v1/usage-metrics", {
    body = body,
    method = "POST",
    headers = headers,
    ssl_verify = ssl
  })
  httpc:close()
  if not res then
    ngx.log(ngx.ERR, "failed to send metrics: ", err)
  end

end

-- Function to retrieve all keys that start with a given prefix

return metrics
