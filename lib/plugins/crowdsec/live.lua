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

function live:new(api_url, cache_expiration, user_agent, bouncing_on_type, time_out, api_key_header)
  local succ, err, forcible = self.cache:set("api_url", api_url)
  if not succ then
    ngx.log(ngx.ERR, "failed to add key api_url in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  local succ, err, forcible = self.cache:set("cache_expiration", cache_expiration)
  if not succ then
    ngx.log(ngx.ERR, "failed to add key cache_expiration in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  local succ, err, forcible = self.cache:set("user_agent", user_agent)
  if not succ then
    ngx.log(ngx.ERR, "failed to add key bouncing_on_type in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  local succ, err, forcible = self.cache:set("bouncing_on_type", bouncing_on_type)
  if not succ then
    ngx.log(ngx.ERR, "failed to add key bouncing_on_type in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  local succ, err, forcible = self.cache:set("time_out", time_out)
  if not succ then
    ngx.log(ngx.ERR, "failed to add key time_out in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  local succ, err, forcible = self.cache:set("api_key_header", api_key_header)
  if not succ then
    ngx.log(ngx.ERR, "failed to add key api_key_header in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  return self
end

--- Live query the API to get the decision for the IP
-- Query the live API to get the decision for the IP in real time
-- @param ip string: the IP to query
-- @return boolean: true if the IP is allowed, false if the IP is blocked
-- @return string: the type of the decision
-- @return string: the origin of the decision
-- @return string: the error message if any

function live:live_query(ip, api_key)
  -- debug: wip
  ngx.log(ngx.INFO, "live_query: " .. ip)
  local cache_expiration = self.cache:get("cache_expiration")
  if not cache_expiration then
    ngx.log(ngx.ERR, "cache_expiration not found in cache")
    return true, nil, nil, nil
  end
  local bouncing_on_type = self.cache:get("bouncing_on_type")
  if not cache_expiration then
    ngx.log(ngx.ERR, "bouncing_on_type not found in cache")
    return true, nil, nil, nil
  end
  local api_url = self.cache:get("api_url")
  if not api_url then
    ngx.log(ngx.ERR, "api_url not found in cache")
    return true, nil, nil, nil
  end

  local timeout = self.cache:get("time_out")
  if not api_url then
    ngx.log(ngx.ERR, "time_out not found in cache")
    return true, nil, nil, nil
  end

  local api_key_header = self.cache:get("api_key_header")
  if not api_key_header then
    ngx.log(ngx.ERR, "api_key_header not found in cache")
    return true, nil, nil, nil
  end

  local user_agent = self.cache:get("user_agent")
  if not user_agent then
    ngx.log(ngx.ERR, "user_agent not found in cache")
    return true, nil, nil, nil
  end

  local ssl_verify = self.cache:get("ssl_verify")
  if not ssl_verify then
    ngx.log(ngx.ERR, "user_agent not found in cache")
    return true, nil, nil, nil
  end

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
    local key = utils.item_to_string(ip, "ip")
    local succ, err, forcible = live.cache:set(key, "allowed/all", cache_expiration, 1)
    --
    ngx.log(ngx.INFO, "Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds") --debug
    if not succ then
      ngx.log(ngx.ERR, "failed to add ip '" .. ip .. "' in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    return true, nil, nil, nil
  end
  local decision = cjson.decode(body)[1]

  -- debug: wip
  ngx.log(ngx.INFO, "Decision: " .. decision.type .. " | " .. decision.value .. " | " .. decision.origin .. " | " .. decision.duration)
  if bouncing_on_type == decision.type or bouncing_on_type == "all" then
    local cache_value = decision.type .. "/" .. decision.origin
    local key = utils.item_to_string(decision.value, decision.scope)
    local succ, err, forcible = live.cache:set(key, cache_value, cache_expiration, 0)
    ngx.log(ngx.INFO, "Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds with decision type'" .. decision.type .. "'with origin'" .. decision.origin ) --debug
    if not succ then
      ngx.log(ngx.ERR, "failed to add ".. decision.value .." : "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    ngx.log(ngx.DEBUG, "Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds")
    return false, decision.type, decision.origin, nil
  else
    return true, nil, nil, nil
  end
end

return live
