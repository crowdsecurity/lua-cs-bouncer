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

-- {
--   "remediation_components": [
--     {
--       "version": "string",
--       "os": {
--         "name": "string",
--         "version": "string"
--       },
--       "metrics": [
--         {
--           "items": [
--             {
--               "name": "string",
--               "value": 0,
--               "unit": "string",
--               "labels": {
--                 "additionalProp1": "string",
--                 "additionalProp2": "string",
--                 "additionalProp3": "string"
--               }
--             }
--           ],
--           "meta": {
--             "window_size_seconds": 0,
--             "utc_now_timestamp": 0
--           }
--         }
--       ],
--       "feature_flags": [
--         "string"
--       ],
--       "utc_startup_timestamp": 0,
--       "type": "string",
--       "name": "string",
--       "last_pull": 0
--     }
--   ],


local cjson = require "cjson"
local http = require "resty.http"
local utils = require "plugins.crowdsec.utils"
local osinfo = require "plugins.crowdsec.osinfo"
local metrics = {}

metrics.__index = metrics
metrics.cache = ngx.shared.crowdsec_cache


-- Constructor for the store
function metrics:new(userAgent)
  local info = osinfo.get_os_info()
  self.cache:set("metrics_data", cjson.encode({
    version = userAgent,
    os = {
      name = info["NAME"];
      version = info["VERSION_ID"];
    },
--    feature_flags = {}, none for now, but this should be an array of strings
    type="lua-bouncer",
    name="nginx bouncer",
    utc_startup_timestamp = ngx.time(),
    last_pull = 0
  }))
end

-- Increment the value of a key or initialize it if it does not exist
function metrics:increment(key, increment)
    increment = increment or 1

    local value, err, forcible = self.cache:incr("metrics_" .. key, increment, 0)
    metrics:add_to_metrics(key)
    if err then
        ngx.log(ngx.ERR, "failed to increment key: ", err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    return value
end

-- Get all metrics as a table (key-value pairs)
function metrics:get_all_keys()
    local keys = metrics.cache:get("metrics_all")
    return utils.split_on_delimiter(keys, ",")
end

-- Add a metric key to the `metrics_all` list
function metrics:add_to_metrics(key)
    local metrics_all = self.cache:get("metrics_all") or ""
    if not metrics_all:find(key) then
        metrics_all = metrics_all .. key .. ","
        local success, err, forcible = self.cache:set("metrics_all", metrics_all)
        if not success then
          ngx.log(ngx.ERR, "failed to set key metrics_all: ", err)
        end
        if forcible then
          ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
        end

    end
end

local function get_information_on_key(key)
  table = utils.split_on_delimiter(key, "/")
  if table[1] == "dropped" and table[2] ~= nil then
    return "dropped" , table[2]
  elseif table[1] == "processed" then
    return "processed", nil
  elseif table[1] == "active_decisions" and table[2] ~= nil then
    return "active_decisions", table[2]
  end
end

-- Export the store data to JSON
function metrics:toJson(window)
  local data_exists = false
  local metrics_array = {}
  local metrics_data = cjson.decode(self.cache:get("metrics_data"))
  local keys = metrics:get_all_keys()
  for  _,key in ipairs(keys) do
    local cache_key = "metrics_" .. key
    local value = self.cache:get(cache_key)
    ngx.log(ngx.INFO, "cache_key: " .. cache_key .. " value: " .. tostring(self.cache:get(cache_key)))--debug
    if value ~= nil then
      local final_key, label = get_information_on_key(key)
      ngx.log(ngx.INFO, "final_key: " .. final_key)
      ngx.log(ngx.INFO, "value: " .. value)
      if label ~= nil then
        ngx.log(ngx.INFO, "label: " .. label)
      end

      if final_key == "processed" then
        table.insert(metrics_array, {
                       name = "processed",
                       value = value,
                       unit = "request",
        })
      elseif final_key == "active_decisions" then
      table.insert(metrics_array, {
                       name = final_key,
                       value = value,
                       unit = "number",
                       labels = {
                         origin = label
                       }
        })
      else
              table.insert(metrics_array, {
                       name = final_key,
                       value = value,
                       unit = "request",
                       labels = {
                         origin = label
                       }
              })

      end
      if not key:find("metrics_active_decisions", 1, true) then
        local success, err = self.cache:delete(cache_key)
        if success then
          ngx.log(ngx.INFO, "Cache key '", cache_key, "' deleted successfully")
        else
          ngx.log(ngx.INFO, "Failed to delete cache key '", cache_key, "': ", err)
        end
      end
      data_exists = true
    end
  end

  if data_exists then
    metrics_data.metrics = {}
    metrics_data.metrics.items = {}
    table.insert(metrics_data.metrics.items, metrics_array)
    local meta = {
      window_size_seconds = window,
      utc_now_timestamp = ngx.time(),
    }

    local items = {}
    local t = {}
    t.items = metrics_array
    t.meta = meta

    metrics_data.metrics = {}
    table.insert(metrics_data.metrics, t)
  end
  local remediation_components = {}
  table.insert(remediation_components,
               metrics_data)

  return cjson.encode({remediation_components=remediation_components})
end

function metrics:sendMetrics(link, headers, ssl, window)
  local body = self:toJson(window) .. "\n"
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
