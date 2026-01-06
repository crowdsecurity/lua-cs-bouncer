local cjson = require "cjson"
local http_client = require "plugins.crowdsec.http_client"
local utils = require "plugins.crowdsec.utils"
local osinfo = require "plugins.crowdsec.osinfo"
local metrics = {}

metrics.__index = metrics
metrics.cache = ngx.shared.crowdsec_cache


-- Constructor for the store
function metrics:new(userAgent, conf)
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
  
  -- Create HTTP client for metrics (with mTLS, API key, and user agent support if configured)
  self.metrics_client = nil
  
  if conf and conf["API_URL"] and conf["API_URL"] ~= "" then
    -- Check if mTLS is enabled
    local use_tls_auth = conf["USE_TLS_AUTH"] and 
                        conf["TLS_CLIENT_CERT_PARSED"] ~= nil and 
                        conf["TLS_CLIENT_KEY_PARSED"] ~= nil
    
    -- Ensure REQUEST_TIMEOUT is a valid number, default to 3000ms if not set
    local request_timeout = tonumber(conf["REQUEST_TIMEOUT"])
    if not request_timeout or request_timeout <= 0 then
      request_timeout = 3000  -- Default to 3 seconds
      ngx.log(ngx.WARN, "REQUEST_TIMEOUT not set or invalid, using default: " .. request_timeout .. "ms")
    end
    
    local client_options = {
      timeouts = {
        connect = request_timeout,
        send = request_timeout,
        read = request_timeout
      },
      ssl_verify = conf["SSL_VERIFY"],
      keepalive_timeout = conf["KEEPALIVE_TIMEOUT"],
      keepalive_pool_size = conf["KEEPALIVE_POOL_SIZE"],
      user_agent = userAgent,
      use_tls_auth = use_tls_auth
    }
    
    -- Add API key only if not using TLS auth
    if not use_tls_auth then
      client_options.api_key = conf["API_KEY"]
      -- Use default API key header from http_client
    end
    
    -- Add mTLS options if TLS auth is enabled (use parsed PEM objects when available)
    if use_tls_auth then
      client_options.ssl_client_cert = conf["TLS_CLIENT_CERT_PARSED"] or conf["TLS_CLIENT_CERT"]
      client_options.ssl_client_priv_key = conf["TLS_CLIENT_KEY_PARSED"] or conf["TLS_CLIENT_KEY"]
    end
    
    local client, err = http_client.new(conf["API_URL"], client_options)
    if client then
      self.metrics_client = client
      ngx.log(ngx.DEBUG, "[METRICS] Created HTTP client with timeouts: connect=" .. request_timeout .. "ms, send=" .. request_timeout .. "ms, read=" .. request_timeout .. "ms")
    else
      ngx.log(ngx.WARN, "Failed to create metrics HTTP client: " .. (err or "unknown"))
    end
  end
end


-- Increment the value of a key or initialize it if it does not exist
-- @param key: the key to increment
-- @param increment: the value to increment the key by
-- @param labels: a table of labels to add to the key
-- @return the new value of the key
function metrics:increment(key, increment, labels)
    increment = increment or 1
    if labels == nil then
      --- Very weird case, should not happen
      --- but no need to crash the bouncer
      ngx.log(ngx.ERR, "no labels")
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
  for  _,key in ipairs(keys or {}) do
    local cache_key = "metrics_" .. key
    local value = self.cache:get(cache_key)
    ngx.log(ngx.DEBUG, "getting data from cache_key: " .. cache_key .. " value: " .. tostring(value))
    if value ~= nil then
      local final_key, labels = get_labels_from_key(key)
      ngx.log(ngx.DEBUG, "Computed final_key: " .. final_key)
      if labels ~= nil then
        for k, v in pairs(labels) do
          ngx.log(ngx.DEBUG, "label: " .. k .. " " .. v)
        end
      end

      table.insert(metrics_array, {
                     name = final_key,
                     value = value,
                     unit = (final_key=="active_decisions" and "ip" or "request"),
                     labels = labels
      })

      if final_key ~= "active_decisions" and final_key ~= "processed" then
        local success, err = self.cache:delete(cache_key)
        if success then
          ngx.log(ngx.DEBUG, "Cache key '", cache_key, "' deleted successfully")
        else
          ngx.log(ngx.ERR, "Failed to delete cache key '", cache_key, "': ", err)
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

function metrics:sendMetrics(window, headers)
  local body = self:toJson(window) .. "\n"
  ngx.log(ngx.DEBUG, "Sending metrics to /v1/usage-metrics")
  ngx.log(ngx.DEBUG, "metrics: " .. body)
  
  -- Use HTTP client if available (created during initialization)
  if not self.metrics_client then
    ngx.log(ngx.ERR, "metrics HTTP client not initialized, cannot send metrics")
    return
  end
  
  -- Build headers (merge any additional headers passed in)
  -- HTTP client will automatically add User-Agent and API key if configured
  local request_headers = headers or {}
  
  local res, err = self.metrics_client:request_uri("/v1/usage-metrics", {
    method = "POST",
    headers = request_headers,
    body = body
  })
  
  if not res then
    ngx.log(ngx.ERR, "failed to send metrics: " .. (err or "unknown"))
  else
    ngx.log(ngx.DEBUG, "metrics status: " .. res.status)
    ngx.log(ngx.DEBUG, "metrics body: " .. body)
  end
end

-- Function to retrieve all keys that start with a given prefix

return metrics
