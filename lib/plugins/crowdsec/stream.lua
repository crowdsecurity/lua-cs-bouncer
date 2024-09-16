local utils = require "plugins.crowdsec.utils"
local cjson = require "cjson"
local metrics = require "plugins.crowdsec.metrics"
local stream = {}

stream.__index = stream
stream.cache = ngx.shared.crowdsec_cache

local function set_refreshing(value)
  local succ, err, forcible = stream.cache:set("refreshing", value)
  if not succ then
    error("Failed to set refreshing key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end
end

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


function stream:new()
  return self
end

--- Query the local API to get the decisions
-- @param api_url string: the URL of the local API
-- @param timeout number: the timeout for the request
-- @param api_key_header string: the header to use for the API key
-- @param api_key string: the API key to use for the request
-- @param user_agent string: the user agent to use for the request
-- @param ssl_verify boolean: whether to verify the SSL certificate or not
-- @param bouncing_on_type string: the type of decision to bounce on
-- @return string: the error message if any
function stream:stream_query(api_url, timeout, api_key_header, api_key, user_agent, ssl_verify, bouncing_on_type)

  -- As this function is running inside coroutine (with ngx.timer.at),
  -- we need to raise error instead of returning them

  if api_url == "" then
    return "No API URL defined"
  end


  set_refreshing(true)

  local is_startup = stream.cache:get("startup")
  ngx.log(ngx.DEBUG, "Stream Query from worker : " .. tostring(ngx.worker.id()) .. " with startup "..tostring(is_startup) .. " | premature: ")
  local link = api_url .. "/v1/decisions/stream?startup=" .. tostring(is_startup)
  local res, err = utils.get_remediation_http_request(link,
                                                      timeout,
                                                      api_key_header,
                                                      api_key,
                                                      user_agent,
                                                      ssl_verify)
  if not res then
    set_refreshing(false)
    return "request failed: " .. err
  end

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
    return "HTTP error while request to Local API '" .. status .. "' with message (" .. tostring(body) .. ")"
  end

  local decisions = cjson.decode(body)

  -- process deleted decisions
  local deleted = {}
  if type(decisions.deleted) == "table" then
    for _, decision in pairs(decisions.deleted) do
      if deleted[decision.origin] == nil then
        deleted[decision.origin] = 0
      else
        deleted[decision.origin] = deleted[decision.origin] + 1
      end
      if decision.type == "captcha" then
        stream.cache:delete("captcha_" .. decision.value)
      end
      local key = utils.item_to_string(decision.value, decision.scope)
      stream.cache:delete(key)
      ngx.log(ngx.DEBUG, "Deleting '" .. key .. "'")
    end
  end

  -- process new decisions
  local added = {}
  if type(decisions.new) == "table" then
    for _, decision in pairs(decisions.new) do
      if added[decision.origin] == nil then
        added[decision.origin] = 0
      else
        added[decision.origin] = added[decision.origin] + 1
      end
      if bouncing_on_type == decision.type or bouncing_on_type == "all" then
        local ttl, err = parse_duration(decision.duration)
        if err ~= nil then
          ngx.log(ngx.ERR, "[Crowdsec] failed to parse ban duration '" .. decision.duration .. "' : " .. err)
        end
        local key = utils.item_to_string(decision.value, decision.scope)
        local succ, err, forcible = stream.cache:set(key, decision.type .. "/" .. decision.origin, ttl, 0) -- 0 means the it's a true remediation decision
        ngx.log(ngx.INFO, "Adding '" .. key .. "' in cache for '" .. tostring(ttl) .. "' seconds " .. decision.type .. "/" .. decision.origin) -- debug
        if not succ then
          ngx.log(ngx.ERR, "failed to add ".. decision.value .." : "..err)
        end
        if forcible then
          ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
        end
      end
    end

    for origin, count in pairs(added) do
      ngx.log(ngx.INFO, "Adding " .. count .. " decisions for " .. origin)
      if deleted[origin] ~= nil then
        added[origin] = count - deleted[origin]
      end
      local og_count = stream.cache:get("metrics_active_decisions/" .. origin)
      if og_count == nil then
        og_count = 0
      end
      metrics:add_to_metrics("active_decisions/" .. origin)
      local succ, err, forcible = stream.cache:set("metrics_active_decisions/" .. origin, og_count + added[origin])
      if not succ then
        ngx.log(ngx.ERR, "failed to add "..  "metrics_active_decisions_" .. origin .." : "..err)
      end
      if forcible then
        ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
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
  ngx.log(ngx.DEBUG, "end of stream_query")
  return nil
end

return stream
