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
    },
--    feature_flags = {}, none for now, but this should be an array of strings
    type="lua-bouncer",
    name="nginx bouncer",
    last_pull = 0
  }))
end

-- Increment the value of a key or initialize it if it does not exist
function metrics:increment(key, increment)
    increment = increment or 1

    local value, err, forcible = self.cache:incr("metrics_" .. key, increment, 0)
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
  local metrics_data = cjson.decode(self.cache:get("metrics_data"))
  metrics_data.meta.utc_now_timestamp = ngx.time()
  local keys = {"CAPI","LAPI","cscli","allowed"}
  for _, key in ipairs(keys) do
    local cache_key = "metrics_" .. key
    local value = self.cache:get(cache_key)
    ngx.log(ngx.INFO, "cache_key: " .. cache_key .. " value: " .. tostring(self.cache:get(cache_key)))--debug
    if value ~= nil then
      table.insert(metrics_array, {
                     name = key,
                     value = value,
                     unit = "number of requests",
      })
      local success, err = cache:delete(key)
      if success then
         ngx.log(ngx.INFO, "Cache key '", key, "' deleted successfully")
      else
         ngx.log(ngx.INFO, "Failed to delete cache key '", key, "': ", err)
      end
    end
  end
  metrics_data.metrics = metrics_array
  local remediation_components = {}
  table.insert(remediation_components,
               metrics_data)
  return cjson.encode({remediation_components=remediation_components})
end

function metrics:sendMetrics(link, headers, ssl)
  local body = self:toJson() .. "\n"
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
  else
    ngx.log(ngx.INFO, "metrics sent: " .. res.status)
    ngx.log(ngx.INFO, "metrics response: " .. body)
  end

end

-- Function to retrieve all keys that start with a given prefix

return metrics
