local utils = require "plugins.crowdsec.utils"
local cjson = require "cjson"
local metrics = require "plugins.crowdsec.metrics"
local stream = {}

stream.__index = stream
stream.cache = ngx.shared.crowdsec_cache

--- Get the number of decisions in the cache for each origin
--- return a table:
  -- table_count[ip_type][origin]
  -- first dimension is the ip type
  -- second dimension is the origin
local function get_decisions_count()
  local table_count = {}
  local keys = stream.cache:get_keys(0)
  for _, key in ipairs(keys) do
    if utils.starts_with(key, "decision_cache/") then
      -- example of decision key value:
      -- Decision key: decision_cache/ipv4_4294967295_165063348
      -- Decision string: ban/lists:crowdsec_proxy/ipv4
      ----
      -- Decision key: decision_cache/ipv4_4294967295_1679502004
      -- decision string ban/lists:crowdsec_public_scanners/ipv4
      local decision_string = stream.cache:get(key)
      local  t = utils.split_on_delimiter(decision_string,"/")
      if t == nil then
        ngx.log(ngx.ERR, "decision string without /" .. decision_string)
        goto continue
      end
      if t[1] == nil then
        ngx.log(ngx.ERR, "decision string without remediation: " .. decision_string)
        goto continue
      end
      if t[2] == nil then
        ngx.log(ngx.ERR, "decision string without origin: " .. decision_string)
        goto continue
      end
      if t[3] == nil then
        ngx.log(ngx.ERR, "decision string without ip type: " .. decision_string)
        goto continue
      end
      if table_count[t[3]] == nil then
        table_count[t[3]] = {}
      end
      if table_count[t[3]][t[2]] == nil then
        ngx.log(ngx.DEBUG, "Adding '" .. t[3] .. "/" .. t[2] .. "' in table_count") --debug
        table_count[t[3]][t[2]] = 1
      else
        table_count[t[3]][t[2]] = table_count[t[3]][t[2]] + 1
      end
      ::continue::
    end
  end
  return table_count
end

local function set_refreshing(value)
  local succ, err, forcible = stream.cache:set("refreshing", value)
  if not succ then
    error("Failed to set refreshing key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end
end

--- Parse a golang duration string and return the number of seconds
--- @param duration string: the duration string to parse
--- @return number: the number of seconds
--- @return string: the error message if any
local function parse_duration(duration)
  local match, err = ngx.re.match(duration, "^((?<hours>[0-9]+)h)?((?<minutes>[0-9]+)m)?(?<seconds>[0-9]+)")
  local ttl = 0
  if not match then
    if err then
      return ttl, err
    end
  end
  if match["hours"] ~= nil and match["hours"] ~= false then
    local hours = tonumber(match["hours"])
    ttl = ttl + (hours * 3600)
  end
  if match["minutes"] ~= nil and match["minutes"] ~= false then
    local minutes = tonumber(match["minutes"])
    ttl = ttl + (minutes * 60)
  end
  if match["seconds"] ~= nil and match["seconds"] ~= false then
    local seconds = tonumber(match["seconds"])
    ttl = ttl + seconds
  end
  return ttl, nil
end

--- Set a value in the stream cache
--- wrapper around ngx.shared.DICT:set using only a prefix to the key
function stream:set(key, value, exptime, flags)
  ngx.log(ngx.DEBUG, "Setting key 'decision_cache/" .. key .. "' in cache with value '" .. value .. "'") -- debug
  local succ, err, forcible = stream.cache:set("decision_cache/" .. key, value, exptime, flags)
  if not succ then
    ngx.log(ngx.ERR, "Failed to set key '" .. key .. "' in cache: " .. err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end
  return succ, err, forcible
end

--- Delete a value from the stream cache
--- wrapper around ngx.shared.DICT:delete using only a prefix to the key
function stream:delete(key)
  return stream.cache:delete("decision_cache/" .. key)
end

--- Get a value from the stream cache
---
function stream:get(key)
  return stream.cache:get("decision_cache/" .. key)
end

function stream:new()
  return self
end

--- Query the local API to get the decisions using API key authentication
-- @param api_url string: the URL of the local API
-- @param timeout number: the timeout for the request
-- @param api_key_header string: the header to use for the API key
-- @param api_key string: the API key to use for the request
-- @param user_agent string: the user agent to use for the request
-- @param ssl_verify boolean: whether to verify the SSL certificate or not
-- @param bouncing_on_type string: the type of decision to bounce on
function stream:stream_query_api(api_url, timeout, api_key_header, api_key, user_agent, ssl_verify, bouncing_on_type)
  -- As this function is running inside coroutine (with ngx.timer.at),
  -- we need to raise error instead of returning them

  if api_url == "" then
    return "No API URL defined"
  end

  set_refreshing(true)

  local is_startup = stream.cache:get("startup")
  ngx.log(ngx.DEBUG, "startup: " .. tostring(is_startup))
  ngx.log(ngx.DEBUG, "Stream Query API from worker : " .. tostring(ngx.worker.id()) .. " with startup "..tostring(is_startup))
  local link = api_url .. "/v1/decisions/stream?startup=" .. tostring(is_startup)

  local res, err = utils.get_remediation_http_request(link,
                                                      timeout,
                                                      api_key_header,
                                                      api_key,
                                                      user_agent,
                                                      ssl_verify)

  if not res then
    set_refreshing(false)
    ngx.log(ngx.ERR, "request to crowdsec lapi " .. link .. " failed: " .. err)
    return "request to crowdsec lapi " .. link .. " failed: " .. err
  end

  return self:stream_query_process(res, bouncing_on_type)
end

--- Query the local API to get the decisions using mTLS authentication
-- @param api_url string: the URL of the local API
-- @param timeout number: the timeout for the request
-- @param user_agent string: the user agent to use for the request
-- @param ssl_verify boolean: whether to verify the SSL certificate or not
-- @param ssl_client_cert string: path to the client certificate file
-- @param ssl_client_priv_key string: path to the client private key file
-- @param bouncing_on_type string: the type of decision to bounce on
function stream:stream_query_tls(api_url, timeout, user_agent, ssl_verify, ssl_client_cert, ssl_client_priv_key, bouncing_on_type)
  -- As this function is running inside coroutine (with ngx.timer.at),
  -- we need to raise error instead of returning them

  if api_url == "" then
    return "No API URL defined"
  end

  set_refreshing(true)

  local is_startup = stream.cache:get("startup")
  ngx.log(ngx.DEBUG, "startup: " .. tostring(is_startup))
  ngx.log(ngx.DEBUG, "Stream Query TLS from worker : " .. tostring(ngx.worker.id()) .. " with startup "..tostring(is_startup))
  local link = api_url .. "/v1/decisions/stream?startup=" .. tostring(is_startup)

  local res, err = utils.get_remediation_http_request_tls(link,
                                                          timeout,
                                                          user_agent,
                                                          ssl_verify,
                                                          ssl_client_cert,
                                                          ssl_client_priv_key)

  if not res then
    set_refreshing(false)
    ngx.log(ngx.ERR, "request to crowdsec lapi " .. link .. " failed: " .. err)
    return "request to crowdsec lapi " .. link .. " failed: " .. err
  end

  return self:stream_query_process(res, bouncing_on_type)
end

--- Process the HTTP response from the CrowdSec API
-- @param res table: the HTTP response object
-- @param bouncing_on_type string: the type of decision to bounce on
function stream:stream_query_process(res, bouncing_on_type)
  local succ, err, forcible = stream.cache:set("last_refresh", ngx.time())
  if not succ then
    ngx.log(ngx.ERR, "Failed to set last_refresh key in cache: " .. err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  local status = res.status
  local body = res.body

  ngx.log(ngx.DEBUG, "Response:" .. tostring(status) .. " | " .. tostring(body))

  if status~=200 then
    set_refreshing(false)
    ngx.log(ngx.ERR, "HTTP error while request to Local API '" .. status .. "' with message (" .. tostring(body) .. ")")
    return "HTTP error while request to Local API '" .. status .. "' with message (" .. tostring(body) .. ")"
  end

  local decisions = cjson.decode(body)

  -- process deleted decisions
  local deleted = {}
  if type(decisions.deleted) == "table" then
    for _, decision in pairs(decisions.deleted) do
      if decision.origin == "lists" and decisions.scenario ~= nil then
        decision.origin = "lists:" .. decision.scenario
      end

      local key, _ = utils.item_to_string(decision.value, decision.scope)
      if key ~= nil then
        self:delete(key)
      else
        ngx.log(ngx.WARN, "[Crowdsec] Failed to parse decision value for deletion: " .. tostring(decision.value) .. " with scope: " .. tostring(decision.scope))
      end
      -- cache space for captcha is different it's used to cache if the captcha has been solved
      if decision.type == "captcha" then
        stream.cache:delete("captcha_" .. decision.value)
      end
      if key ~= nil then
        local cache_value = stream.cache:get(key)
        if cache_value ~= nil then
          stream.cache:delete(key)
          if deleted[decision.origin] == nil then
            deleted[decision.origin] = 1
          else
            deleted[decision.origin] = deleted[decision.origin] + 1
          end
        end
        ngx.log(ngx.DEBUG, "Deleting '" .. key .. "'")
      else
        ngx.log(ngx.WARN, "[Crowdsec] Failed to parse decision value for cache lookup: " .. tostring(decision.value) .. " with scope: " .. tostring(decision.scope))
      end
    end
  end

  -- process new decisions
  if type(decisions.new) == "table" then
    for _, decision in pairs(decisions.new) do
      if decision.origin == "lists" and decision.scenario ~= nil then
        decision.origin = "lists:" .. decision.scenario
      end
      if bouncing_on_type == decision.type or bouncing_on_type == "all" then
        local ttl, err = parse_duration(decision.duration)
        if err ~= nil then
          ngx.log(ngx.ERR, "[Crowdsec] failed to parse ban duration '" .. decision.duration .. "' : " .. err)
        end
        local key, ip_type = utils.item_to_string(decision.value, decision.scope)
        if key ~= nil and ip_type ~= nil then
          local succ, err, forcible = self:set(key, decision.type .. "/" .. decision.origin .. "/" .. ip_type, ttl, 0) -- 0 means the it's a true remediation decision
          ngx.log(ngx.DEBUG, "Adding '" .. key .. "' in cache for '" .. tostring(ttl) .. "' seconds " .. decision.type .. "/" .. decision.origin .. "/" .. ip_type) -- debug
          if not succ then
            ngx.log(ngx.ERR, "failed to add ".. decision.value .." : "..err)
          end
          if forcible then
            ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
          end
        else
          ngx.log(ngx.WARN, "[Crowdsec] Failed to parse decision value: " .. tostring(decision.value) .. " with scope: " .. tostring(decision.scope) .. " - skipping decision")
        end
      end
    end
  end

  -- not startup anymore after first callback
  local succ, err, forcible = stream.cache:set("startup", false)
  if not succ then
    ngx.log(ngx.ERR, "failed to set startup key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  set_refreshing(false)
  ngx.log(ngx.DEBUG, "end of stream_query_process")
  return nil
end

function stream:refresh_metrics()
  local table_count = get_decisions_count()
    for ip_type, table_origin in pairs(table_count) do
      for origin, count in pairs(table_origin) do
        local labels = {origin = origin, ip_type = ip_type}
        metrics:add_to_metrics("active_decisions/" .. utils.table_to_string(labels))
        local succ, err, forcible = stream.cache:set("metrics_active_decisions/" .. utils.table_to_string(labels), count)
        if not succ then
          ngx.log(ngx.ERR, "failed to add "..  "metrics_active_decisions_" .. origin .. "/" .. ip_type .. ": ".. err)
        end
        if forcible then
          ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
        end
      end
    end
end

return stream
