local cjson = require "cjson"
local utils = require "plugins.crowdsec.utils"

local live = {}
live.__index = live

live.cache = ngx.shared.crowdsec_cache

--- Create a new live object
-- Create a new live object to query the live API
-- @param api_url string: the URL of the live API
-- @param cache_expiration number: the expiration time of the cache
-- @param bouncing_on_type string: the type of decision to bounce on
-- @param time_out number: the time out of the http lapi request
-- @param api_key_header string: the header to use for the API key
-- @return live: the live object

function live:new()
  return self
end

--- Live query the API to get the decision for the IP
-- Query the live API to get the decision for the IP in real time
-- @param ip string: the IP to query
-- @param api_url string: the URL of the LAPI
-- @param timeout number: the timeout of the request to lapi
-- @param cache_expiration number: the expiration time of the cache
-- @param api_key_header string: the authorization header to use for the lapi request
-- @param api_key string: the API key to use for the lapi request
-- @param user_agent string: the user agent to use for the lapi request
-- @param ssl_verify boolean: whether to verify the SSL certificate or not
-- @param bouncing_on_type string: the type of decision to bounce on
-- @return boolean: true if the IP is allowed, false if the IP is blocked
-- @return string: the type of the decision
-- @return string: the origin of the decision
-- @return string: the error message if any

function live:live_query(ip, api_url, timeout, cache_expiration, api_key_header, api_key, user_agent, ssl_verify, bouncing_on_type)

  local link = api_url .. "/v1/decisions?ip=" .. ip
  -- function M.get_remediation_http_request(link,timeout, api_key_header, api_key, user_agent,ssl_verify)

  local res, err = utils.get_remediation_http_request(link, timeout, api_key_header, api_key, user_agent, ssl_verify)
  if not res then
    return true, nil, nil, "request failed: ".. err
  end
  -- debug: wip
  ngx.log(ngx.INFO, "request" .. res.body)
  local status = res.status
  local body = res.body
  if status~=200 then
    return true, nil, nil, "Http error " .. status .. " while talking to LAPI (" .. link .. ")"
  end
  if body == "null" then -- no result from API, no decision for this IP
    -- set ip in cache and DON'T block it
    local key,_ = utils.item_to_string(ip, "ip")
    local succ, err, forcible = live.cache:set(key, "none", cache_expiration, 1)
    --
    ngx.log(ngx.INFO, "Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds") --debug
    if not succ then
      ngx.log(ngx.ERR, "failed to add ip '" .. ip .. "' in cache: ".. err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    return true, nil, nil, nil
  end
  local decision = cjson.decode(body)[1]

  -- debug: wip
  ngx.log(ngx.INFO, "Decision: " .. decision.type .. " | " .. decision.value .. " | " .. decision.origin .. " | " .. decision.duration)
  ngx.log(ngx.INFO, "Bouncing on type: " .. bouncing_on_type)
  if bouncing_on_type == decision.type or bouncing_on_type == "all" then
    if decision.origin == "lists" and decision.scenario ~= nil then
      decision.origin = "lists:" .. decision.scenario
    end
    local cache_value = decision.type .. "/" .. decision.origin
    local key,_ = utils.item_to_string(decision.value, decision.scope)
    local succ, err, forcible = live.cache:set(key, cache_value, cache_expiration, 0)
    ngx.log(ngx.INFO, "Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds with decision type'" .. decision.type .. "'with origin'" .. decision.origin ) --debug
    if not succ then
      ngx.log(ngx.ERR, "failed to add ".. decision.value .." : "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    -- debug: wip
    ngx.log(ngx.DEBUG, "Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds")
    ngx.log(ngx.INFO, "Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds")
    return false, decision.type, decision.origin, nil
  else
    return true, nil, nil, nil
  end
end

return live
