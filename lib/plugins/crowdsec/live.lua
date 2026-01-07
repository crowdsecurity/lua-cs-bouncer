local cjson = require "cjson"
local utils = require "plugins.crowdsec.utils"
local http_client = require "plugins.crowdsec.http_client"

local live = {}
live.__index = live

live.cache = ngx.shared.crowdsec_cache

--- Create a new live object
-- Create a new live object to query the live API
-- @param conf table: Runtime configuration table
-- @param user_agent string: User agent string
-- @return live: the live object

function live:new(conf, user_agent)
  local instance = setmetatable({}, self)
  
  -- Create single HTTP client (handles mTLS, API key, and user agent if configured)
  instance.API_CLIENT = nil
  
  if conf["API_URL"] ~= "" then
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
      user_agent = user_agent,
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
      instance.API_CLIENT = client
      ngx.log(ngx.DEBUG, "[LIVE] Created HTTP client with timeouts: connect=" .. request_timeout .. "ms, send=" .. request_timeout .. "ms, read=" .. request_timeout .. "ms")
    else
      ngx.log(ngx.WARN, "Failed to create API HTTP client: " .. (err or "unknown"))
    end
  end
  
  return instance
end

--- Live query the API to get the decision for the IP
-- Query the live API to get the decision for the IP in real time
-- Uses API key authentication if mTLS is not configured, otherwise uses mTLS
-- @param ip string: the IP to query
-- @param cache_expiration number: the expiration time of the cache
-- @param bouncing_on_type string: the type of decision to bounce on
-- @return boolean: true if the IP is allowed, false if the IP is blocked
-- @return string: the type of the decision
-- @return string: the origin of the decision
-- @return string: the error message if any
function live:live_query(ip, cache_expiration, bouncing_on_type)
  if not self.API_CLIENT then
    return true, nil, nil, "HTTP client not available"
  end
  
  -- Build path (base path from API_URL will be prepended by request_uri)
  local path = "/v1/decisions?ip=" .. ip
  local full_url = self.API_CLIENT:build_url(path)
  
  local res, err = self.API_CLIENT:request_uri(path, {
    method = "GET"
  })

  if err ~= nil or not res then
    ngx.log(ngx.ERR, "failed to query LAPI: " .. (err or "unknown"))
    return true, nil, nil, err or "request failed"
  end

  return self:live_query_process(res, ip, cache_expiration, bouncing_on_type, full_url)
end

--- Process the HTTP response from the CrowdSec API for live queries
-- @param res table: the HTTP response object
-- @param ip string: the IP being queried
-- @param cache_expiration number: the expiration time of the cache
-- @param bouncing_on_type string: the type of decision to bounce on
-- @param link string: the API link for error reporting
-- @return boolean: true if the IP is allowed, false if the IP is blocked
-- @return string: the type of the decision
-- @return string: the origin of the decision
-- @return string: the error message if any
function live:live_query_process(res, ip, cache_expiration, bouncing_on_type, link)
  local status = res.status
  local body = res.body
  if status~=200 then
    return true, nil, nil, "Http error " .. status .. " while talking to LAPI (" .. link .. ")"
  end

  --- TODO (after metrics merge) see if following code can be refactored
  if body == "null" then -- no result from API, no decision for this IP
    -- set ip in cache and DON'T block it
    local key,_ = utils.item_to_string(ip, "ip")
    if key == nil then
      ngx.log(ngx.WARN, "[Crowdsec] Failed to parse IP address for caching: " .. tostring(ip) .. " - skipping cache")
      return true, nil, nil, nil
    end
    local succ, err, forcible = live.cache:set("decision_cache/" .. key, "none", cache_expiration, 1)
    --
    ngx.log(ngx.DEBUG, "[CACHE] Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds") --debug
    if not succ then
      ngx.log(ngx.ERR, "failed to add ip '" .. ip .. "' in cache: ".. err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    return true, nil, nil, nil
  end
  
  -- Validate body exists and is not empty before decoding
  if not body or body == "" then
    return true, nil, nil, "Empty or missing response body from LAPI"
  end
  
  local decode_ok, decoded_body = pcall(cjson.decode, body)
  if not decode_ok then
    return true, nil, nil, "Failed to decode JSON response from LAPI: " .. tostring(decoded_body)
  end
  
  if not decoded_body or #decoded_body == 0 then
    return true, nil, nil, "Empty decisions array from LAPI"
  end
  
  local decision = decoded_body[1]

  if decision.origin == "lists" and decision.scenario ~= nil then
    decision.origin = "lists:" .. decision.scenario
  end
  local cache_value = decision.type .. "/" .. decision.origin
  local key,_ = utils.item_to_string(decision.value, decision.scope)
  if key == nil then
    ngx.log(ngx.WARN, "[Crowdsec] Failed to parse decision value for caching: " .. tostring(decision.value) .. " with scope: " .. tostring(decision.scope) .. " - skipping cache")
    return true, nil, nil, nil
  end
  local succ, err, forcible = live.cache:set("decision_cache/" .. key, cache_value, cache_expiration, 0)
  ngx.log(ngx.DEBUG, "[CACHE] Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds with decision type'" .. decision.type .. "'with origin'" .. decision.origin ) --debug
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
