package.path = package.path .. ";./?.lua"

local config = require "plugins.crowdsec.config"
local iputils = require "plugins.crowdsec.iputils"
local http = require "resty.http"
local cjson = require "cjson"
local ipmatcher = require "resty.ipmatcher"
local bit = require 'bitop.funcs'


-- contain runtime = {}
local runtime = {}
runtime.remediations = {}
runtime.remediations["1"] = "ban"
runtime.remediations["2"] = "captcha"


local csmod = {}

-- init function
function csmod.init(configFile, userAgent)
  local conf, err = config.loadConfig(configFile)
  if conf == nil then
    return nil, err
  end
  runtime.conf = conf
  runtime.userAgent = userAgent
  runtime.cache = ngx.shared.crowdsec_cache

  -- if stream mode, add callback to stream_query and start timer
  if runtime.conf["MODE"] == "stream" then
    runtime.cache:set("startup", true)
    runtime.cache:set("first_run", true)
  end

  return true, nil
end

function http_request(link)
  local httpc = http.new()
  httpc:set_timeout(runtime.conf['REQUEST_TIMEOUT'])
  local res, err = httpc:request_uri(link, {
    method = "GET",
    headers = {
      ['Connection'] = 'close',
      ['X-Api-Key'] = runtime.conf["API_KEY"],
      ['User-Agent'] = runtime.userAgent
    },
  })
  return res, err
end

function parse_duration(duration)
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

function get_remediation_id(remediation)
  for key, value in pairs(runtime.remediations) do
    if value == remediation then
      return tonumber(key)
    end
  end
  return nil
end

function item_to_string(item, scope)
  local ip, cidr
  if scope:lower() == "ip" then
    ip = item
  end
  if scope:lower() == "range" then
    ip, cidr = iputils.splitRange(item, scope)
  end

  local ip_version, ip_network_address
  local res = ipmatcher.parse_ipv4(ip)
  if res ~= false then
    ip_version = "ipv4"
    ip_network_address = res
    if cidr == nil then
      cidr = 32
    end
  end
  local res = ipmatcher.parse_ipv6(ip)
  if res ~= false then
    ip_version = "ipv6"
    ip_network_address = iputils.concatIPv6(res)
    if cidr == nil then
      cidr = 128
    end
  end
  if ip_version == nil then
    return "normal_"..item
  end
  local ip_netmask = iputils.cidrToInt(cidr, ip_version)

  return ip_version.."_"..ip_netmask.."_"..ip_network_address
end

function stream_query()
  -- As this function is running inside coroutine (with ngx.timer.every), 
  -- we need to raise error instead of returning them
  local is_startup = runtime.cache:get("startup")
  ngx.log(ngx.DEBUG, "Stream Query from worker : " .. tostring(ngx.worker.id()) .. " with startup "..tostring(is_startup))
  local link = runtime.conf["API_URL"] .. "/v1/decisions/stream?startup=" .. tostring(is_startup)
  local res, err = http_request(link)
  if not res then
    if ngx.timer.every == nil then
      local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], stream_query)
      if not ok then
        error("Failed to create the timer: " .. (err or "unknown"))
      end
    end    
    error("request failed: ".. err)
  end

  local status = res.status
  local body = res.body
  if status~=200 then
    if ngx.timer.every == nil then
      local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], stream_query)
      if not ok then
        error("Failed to create the timer: " .. (err or "unknown"))
      end
    end
    error("Http error " .. status .. " with message (" .. tostring(body) .. ")")
  end

  local decisions = cjson.decode(body)
  -- process deleted decisions
  if type(decisions.deleted) == "table" then
    if not is_startup then
      for i, decision in pairs(decisions.deleted) do
        local key = item_to_string(decision.value, decision.scope)
        runtime.cache:delete(key)
        ngx.log(ngx.DEBUG, "Deleting '" .. key .. "'")
      end
    end
  end

  -- process new decisions
  if type(decisions.new) == "table" then
    for i, decision in pairs(decisions.new) do
      if runtime.conf["BOUNCING_ON_TYPE"] == decision.type or runtime.conf["BOUNCING_ON_TYPE"] == "all" then
        local ttl, err = parse_duration(decision.duration)
        if err ~= nil then
          ngx.log(ngx.ERR, "[Crowdsec] failed to parse ban duration '" .. decision.duration .. "' : " .. err)
        end
        local remediation_id = get_remediation_id(decision.type)
        if remediation_id == nil then
          remediation_id = 1
        end
        local key = item_to_string(decision.value, decision.scope)
        local succ, err, forcible = runtime.cache:set(key, false, ttl, remediation_id)
        if not succ then
          ngx.log(ngx.ERR, "failed to add ".. decision.value .." : "..err)
        end
        if forcible then
          ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
        end
        ngx.log(ngx.DEBUG, "Adding '" .. key .. "' in cache for '" .. ttl .. "' seconds")
      end
    end
  end

  -- not startup anymore after first callback
  runtime.cache:set("startup", false)
  
  -- re-occuring timer if there is no timer.every available
  if ngx.timer.every == nil then
    local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], stream_query)
    if not ok then
      error("Failed to create the timer: " .. (err or "unknown"))
    end
  end
  return nil
end

function live_query(ip)
  local link = runtime.conf["API_URL"] .. "/v1/decisions?ip=" .. ip
  local res, err = http_request(link)
  if not res then
    return true, "request failed: ".. err
  end

  local status = res.status
  local body = res.body
  if status~=200 then
    return true, "Http error " .. status .. " while talking to LAPI (" .. link .. ")" 
  end
  if body == "null" then -- no result from API, no decision for this IP
    -- set ip in cache and DON'T block it
    runtime.cache:set(ip, true,runtime.conf["CACHE_EXPIRATION"])
    return true, nil
  end
  local decision = cjson.decode(body)[1]

  if runtime.conf["BOUNCING_ON_TYPE"] == decision.type or runtime.conf["BOUNCING_ON_TYPE"] == "all" then
    -- set ip in cache and block it
    runtime.cache:set(ip, false,runtime.conf["CACHE_EXPIRATION"])
    return false, nil
  else
    return true, nil
  end
end


function csmod.allowIp(ip)
  if runtime.conf == nil then
    return true, runtime.conf["BOUNCING_ON_TYPE"], "Configuration is bad, cannot run properly"
  end

  -- if it stream mode and startup start timer
  if runtime.cache:get("first_run") == true then
    local ok, err
    if ngx.timer.every == nil then
      ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], stream_query)
    else
      ok, err = ngx.timer.every(runtime.conf["UPDATE_FREQUENCY"], stream_query)
    end
    if not ok then
      runtime.cache:set("first_run", true)
      return true, runtime.conf["BOUNCING_ON_TYPE"], "Failed to create the timer: " .. (err or "unknown")
    end
    runtime.cache:set("first_run", false)
    ngx.log(ngx.DEBUG, "Timer launched")
  end

  local key = item_to_string(ip, "ip")
  local key_parts = {}
  for i in key.gmatch(key, "([^_]+)") do
    table.insert(key_parts, i)
  end
  local key_type = key_parts[1]
  if key_type == "normal" then
    local in_cache, remediation_id = runtime.cache:get(key)
    if in_cache ~= nil then -- we have it in cache
      ngx.log(ngx.DEBUG, "'" .. key .. "' is in cache")
      return in_cache, runtime.remediations[tostring(remediation_id)], nil
    end
  end
  
  local ip_network_address = tonumber(key_parts[3])
  local netmasks = iputils.netmasks_by_key_type[key_type]
  for _, netmask in pairs(netmasks) do
    local item = key_type.."_"..netmask.."_"..tostring(bit.band(ip_network_address, netmask))
    in_cache, remediation_id = runtime.cache:get(item)
    if in_cache ~= nil then -- we have it in cache
      ngx.log(ngx.DEBUG, "'" .. key .. "' is in cache")
      return in_cache, runtime.remediations[tostring(remediation_id)], nil
    end
  end

  -- if live mode, query lapi
  if runtime.conf["MODE"] == "live" then
    local ok, err = live_query(ip)
    return ok, runtime.conf["BOUNCING_ON_TYPE"], err
  end
  return true, runtime.conf["BOUNCING_ON_TYPE"], nil
end


-- Use it if you are able to close at shuttime
function csmod.close()
end

return csmod
