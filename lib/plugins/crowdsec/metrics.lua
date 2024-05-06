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
function metrics:increment(location_id,key, increment)
    increment = increment or 1

    local value, err, forcible = self.cache:incr("metrics" .. key .. "_" .. location_id, increment, 0)
    if err then
        ngx.log(ngx.ERR, "failed to increment key: ", err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    return value
end

local function extract_specific_parts(input_string)
    -- The pattern below captures two groups of characters separated by underscores
    local first_part, second_part = string.match(input_string, "^metrics_([^_]+)_([^_]+)_")
    return first_part, second_part
end

-- Export the store data to JSON
function metrics:toJson()
  local metrics_array = {}
  local filtered_keys = self:get_keys_with_prefix("metrics")
  for _, key in pairs(filtered_keys) do
    local metric, location_id = extract_specific_parts(key)
    table.insert(metrics_array, {
      name = metric,
      value = self.cache:get(key),
      unit = "number of requests",
      labels = {
        location_id = location_id
      }
    })
  end
  return cjson.encode({self.metrics_data, metrics_array})
end

function metrics:sendMetrics(link, headers, ssl)
  local body = self:toJson()
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
function metrics:get_keys_with_prefix(prefix)
    local keys = self.cache:get_keys(0)  -- Retrieve all keys,
    local filtered_keys = {}

    for _, key in ipairs(keys) do
        if string.sub(key, 1, string.len(prefix)) == prefix then
            table.insert(filtered_keys, key)
        end
    end

    return filtered_keys
end

return metrics
