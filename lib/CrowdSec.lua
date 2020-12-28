package.path = package.path .. ";./lib/?.lua"

local config = require "config"
local lrucache = require "lrucache"
local logging = require "logging"
local log_file = require "logging.file"
local http = require("socket.http")
local https = require("ssl.https")


-- contain runtime = {}
local runtime = {}

function ipv6toInt ( str )
    local o1,o2,o3,o4,o5,o5,o6,o7,o8 = str:match("(%w+):(%w+):(%w+):(%w+):(%w+):(%w+):(%w+):(%w+)" )
    print (o1)
    local num = 0
    if o1 ~= nil then
        num=num+2^56*tonumber(o1,16)
    end
    if o2 ~= nil then
        num=num+2^48*tonumber(o2,16)
    end
    if o3 ~= nil then
        num=num+2^40*tonumber(o3,16)
    end
    if o4 ~= nil then
        num=num+2^32*tonumber(o4,16)
    end
    if o5 ~= nil then
        num=num+2^24*tonumber(o5,16)
    end
    if o6 ~= nil then
        num=num+2^16*tonumber(o6,16)
    end
    if o7 ~= nil then
        num=num+2^8*tonumber(o7,16)
    end
    if o8 ~= nil then
        num=num+tonumber(o8,16)
    end
    return num
end

function ipToInt( str )
	local num = 0
	if str and type(str)=="string" then
                if str:find(".", 4,true) then
		            local o1,o2,o3,o4 = str:match("(%d+)%.(%d+)%.(%d+)%.(%d+)" )
		            num = 2^24*o1 + 2^16*o2 + 2^8*o3 + o4
                else
                    num = ipv6toInt (str)
                end
	end
    return num
end


local csmod = {}

-- init function
function csmod.init(configFile, userAgent)
  local conf, err = config.loadConfig(configFile)
  if conf == nil then
    return nil, err
  end
  runtime.conf = conf

  local logger = log_file(conf["LOG_FILE"])
  runtime.logger = logger
  runtime.userAgent = userAgent
  local c, err = lrucache.new(conf["CACHE_SIZE"])
  if not c then
    error("failed to create the cache: " .. (err or "unknown"))
  end
  runtime.cache = c
  return true, nil
end


function csmod.allowIp(ip)
  if runtime.conf == nil then
    return nil, "Configuration is bad, cannot run properly"
  end
  local resp = runtime.cache:get(ip)

  if resp ~= nil then -- we have it in cache
    runtime.logger:debug("'" .. ip .. "' is in cache")
    return resp, nil
  end

  -- not in cache
  local link = runtime.conf["API_URL"] .. "/v1/decisions?ip=" .. ip
  local resp = {}
  if link:find("https://") == 1 then
      one, code, headers, status = https.request{
                                            url = link,
                                            headers = { 
                                              ['Connection'] = 'close',
                                              ['X-Api-Key'] = runtime.conf["API_KEY"],
                                              ['User-Agent'] = runtime.userAgent
                                            },    
                                            content_type = 'application/json',    
                                            sink = ltn12.sink.table(resp),
                                            protocol = "tlsv1",
                                            options = "all",
                                            verify = "none",
                                            }
  else
      body, code, headers = http.request{
                                    url = link,
                                    headers = { 
                                      ['Connection'] = 'close',
                                      ['X-Api-Key'] = runtime.conf["API_KEY"],
                                      ['User-Agent'] = runtime.userAgent
                                    },    
                                    content_type = 'application/json',    
                                    sink = ltn12.sink.table(resp)
                                    }
  end
  
  resp = table.concat(resp)
  if code~=200 then 
    ngx.log(ngx.ERR, "[Crowdsec] Http error " .. code .. " while talking to LAPI (" .. link .. ")") -- API error, don't block IP
    runtime.logger:error("Http error " .. code .. " while talking to LAPI (" .. link .. ")")
    return true, nil 
  end
  if resp == "null" then -- no result from API, no decision for this IP
    -- set ip in cache and DON'T block it
    runtime.cache:set(ip, true,runtime.conf["CACHE_EXPIRATION"])
    return true, nil
  end
  -- set ip in cache and block it
  runtime.cache:set(ip, false,runtime.conf["CACHE_EXPIRATION"])
  return false, nil
end


-- Use it if you are able to close at shuttime
function csmod.close()
end

return csmod
