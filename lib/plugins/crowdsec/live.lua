local cjson = require "cjson"
local utils = require "plugins.crowdsec.utils"

local live = {}
live.__index = live

live.cache = ngx.shared.crowdsec_cache

--- Create a new live object with HTTP client
--- @param api_url string: the API URL for LAPI
--- @param timeout number: request timeout
--- @param api_key_header string: API key header name  
--- @param api_key string: API key value
--- @param user_agent string: user agent string
--- @param ssl_verify boolean: whether to verify SSL certificates
--- @return live: the live object
--- @return string: error message if any
function live:new(api_url, timeout, api_key_header, api_key, user_agent, ssl_verify)
  local instance = setmetatable({}, live)
  
  if api_url and api_url ~= "" then
    local timeout_config = {
      connect = 1000,
      send = timeout or 5000,
      read = timeout or 5000
    }
    
    local httpc, connection_config, err = utils.create_http_client(
      api_url, 
      timeout_config, 
      ssl_verify, 
      user_agent, 
      api_key_header, 
      api_key
    )
    
    if err then
      ngx.log(ngx.ERR, "Failed to create HTTP client for live mode: " .. err)
      return instance, err
    end
    
    instance.httpc = httpc
    instance.connection_config = connection_config
    instance.cache_expiration = 60 -- default cache expiration
    instance.bouncing_on_type = "all" -- default bouncing type
    
    ngx.log(ngx.INFO, "Live mode HTTP client initialized successfully")
  end
  
  return instance, nil
end

--- Live query the API to get the decision for the IP
--- @param ip string: the IP to query
--- @param cache_expiration number: optional cache expiration override
--- @param bouncing_on_type string: optional bouncing type override
--- @return boolean: true if the IP is allowed, false if the IP is blocked
--- @return string: the type of the decision
--- @return string: the origin of the decision
--- @return string: the error message if any
function live:live_query(ip, cache_expiration, bouncing_on_type)
  if not self.httpc or not self.connection_config then
    return true, nil, nil, "HTTP client not initialized"
  end
  
  cache_expiration = cache_expiration or self.cache_expiration
  bouncing_on_type = bouncing_on_type or self.bouncing_on_type

  local path = "v1/decisions?ip=" .. ip
  local res, err = utils.make_http_request(self.httpc, self.connection_config, path)

  if not res then
    ngx.log(ngx.ERR, "failed to query LAPI: " .. err)
    return true, nil, nil, "request failed: " .. err
  end

  local status = res.status
  local body = res.body
  if status ~= 200 then
    return true, nil, nil, "Http error " .. status .. " while talking to LAPI"
  end

  if body == "null" then -- no result from API, no decision for this IP
    -- set ip in cache and DON'T block it
    local key,_ = utils.item_to_string(ip, "ip")
    local succ, err, forcible = live.cache:set("decision_cache/" .. key, "none", cache_expiration, 1)
    
    ngx.log(ngx.DEBUG, "[CACHE] Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds")
    if not succ then
      ngx.log(ngx.ERR, "failed to add ip '" .. ip .. "' in cache: " .. err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    return true, nil, nil, nil
  end

  local decision = cjson.decode(body)[1]

  if decision.origin == "lists" and decision.scenario ~= nil then
    decision.origin = "lists:" .. decision.scenario
  end
  local cache_value = decision.type .. "/" .. decision.origin
  local key,_ = utils.item_to_string(decision.value, decision.scope)
  local succ, err, forcible = live.cache:set("decision_cache/" .. key, cache_value, cache_expiration, 0)
  ngx.log(ngx.DEBUG, "[CACHE] Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds with decision type'" .. decision.type .. "'with origin'" .. decision.origin)
  if not succ then
    ngx.log(ngx.ERR, "failed to add ".. decision.value .." : "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end
  if bouncing_on_type == decision.type or bouncing_on_type == "all" then
    return false, decision.type, decision.origin, nil
  else
    return true, nil, nil, nil
  end
end

return live
