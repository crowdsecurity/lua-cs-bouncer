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
    type="lua-bouncer",
    name="nginx bouncer",
    utc_startup_timestamp = ngx.time(),
  }))
end


-- Increment the value of a key or initialize it if it does not exist
-- @param key: the key to increment
-- @param increment: the value to increment the key by
-- @param labels: a table of labels to add to the key
-- @return the new value of the key
function metrics:increment(key, increment, labels)
    increment = increment or 1
    if labels == nil then
      ngx.log(ngx.INFO, "no labels")
    end

    -- keys could look like:
    -- processed/ip_version=ipv4&
    -- active_decisions/ip_version=ipv4&decision_type=ban&
    key = key .. "/" .. utils.table_to_string(labels)
    local value, err, forcible = self.cache:incr("metrics_" .. key, increment, 0)
    metrics:add_to_metrics(key)
    if err then
        ngx.log(ngx.ERR, "failed to increment key: " .. key, err)
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

--- Get the labels from a cache key
--- As labels are stored in the cache key
--- we need to extract them from the key
--- @param key string key: the cache key to extract the labels from
--- @return string the key without the labels and the labels as a table
--- @return table labels as a table
local function get_labels_from_key(key)
  local table = utils.split_on_delimiter(key, "/")
  local labels = {}
  if table == nil then
    return "", {}
  else
    if table[2] ~= nil then
      labels = utils.string_to_table(table[2])
    end
  end
  return table[1], labels
end

-- Export the store data to JSON
function metrics:toJson(window)
  local metrics_array = {}
  local metrics_data = self.cache:get("metrics_data")
  local keys = metrics:get_all_keys()
  for  _,key in ipairs(keys) do
    local cache_key = "metrics_" .. key
    local value = self.cache:get(cache_key)
    ngx.log(ngx.INFO, "cache_key: " .. cache_key .. " value: " .. tostring(self.cache:get(cache_key)))--debug
    if value ~= nil then
      ngx.log(ngx.INFO, "key: " .. key)
      local final_key, labels = get_labels_from_key(key)
      ngx.log(ngx.INFO, "final_key: " .. final_key)
      ngx.log(ngx.INFO, "value: " .. value)
      if labels ~= nil then
        for k, v in pairs(labels) do
          ngx.log(ngx.INFO, "label: " .. k .. " " .. v)
        end
      end

      if final_key == "processed" then
        table.insert(metrics_array, {
                       name = "processed",
                       value = value,
                       unit = "request",
                       labels = labels
        })
      elseif final_key == "active_decisions" then
        table.insert(metrics_array, {
                       name = final_key,
                       value = value,
                       unit = "ip",
                       labels = labels
        })
      else
        table.insert(metrics_array, {
                       name = final_key,
                       value = value,
                       unit = "request",
                       labels = labels
        })

      end

      if final_key ~= "active_decisions" and final_key ~= "processed" then
        local success, err = self.cache:delete(cache_key)
        if success then
          ngx.log(ngx.INFO, "Cache key '", cache_key, "' deleted successfully")
        else
          ngx.log(ngx.INFO, "Failed to delete cache key '", cache_key, "': ", err)
        end
      else
        if final_key == "processed" then
          self.cache:set(cache_key, 0)
        end
      end
    end
  end

  local remediation_components = {}
  local remediation_component = cjson.decode(metrics_data)
  remediation_component["feature_flags"] = setmetatable({}, cjson.array_mt)
  remediation_component["metrics"]= {
    {
      items = metrics_array,
      meta = {
        utc_now_timestamp = ngx.time(),
        window_size_seconds = window
      }
    }
  }
  table.insert(remediation_components, remediation_component)
  return cjson.encode({log_processors = cjson.null, remediation_components = remediation_components})
end

function metrics:sendMetrics(link, headers, ssl, window)
  local body = self:toJson(window) .. "\n"
  ngx.log(ngx.DEBUG, "Sending metrics to " .. link .. "/v1/usage-metrics")
  ngx.log(ngx.DEBUG, "metrics: " .. body)
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
    ngx.log(ngx.DEBUG, "metrics status: " .. res.status)
    ngx.log(ngx.DEBUG, "metrics response: " .. body)
  end

end

-- Function to retrieve all keys that start with a given prefix

return metrics
