package.path = package.path .. ";./lib/?.lua"

local config = require "config"
local lrucache = require "lrucache"
local logging = require "logging"
local log_file = require "logging.file"
local socket = require "socket"
local http = require("socket.http")
local https = require("ssl.https")


-- contain runtime = {}
local runtime = {}


function ipToInt( str )
	local num = 0
	if str and type(str)=="string" then
		local o1,o2,o3,o4 = str:match("(%d+)%.(%d+)%.(%d+)%.(%d+)" )
		num = 2^24*o1 + 2^16*o2 + 2^8*o3 + o4
	end
    return num
end


local csmod = {}

function getLogLevel( level )
  if level and type(level)=="string" then
    if level:upper() == "INFO" then
      return logging.INFO
    end
    if level:upper() == "WARN" then
      return logging.WARN
    end
    if level:upper() == "DEBUG" then
      return logging.DEBUG
    end
    if level:upper() == "ERROR" then
      return logging.ERROR
    end
    if level:upper() == "FATAL" then
      return logging.FATAL
    end
  end
  return logging.INFO
end

-- init function
function csmod.init(configFile, userAgent)
  local conf, err = config.loadConfig(configFile)
  if conf == nil then
    return nil, err
  end
  runtime.conf = conf

  local logger = log_file(conf["LOG_FILE"])
  logger:setLevel (getLogLevel(conf["LOG_LEVEL"]))
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
  local one, body, code, headers, status

  if link:find("https://") == 1 then
      https.TIMEOUT = runtime.conf['REQUEST_TIMEOUT']
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
                                            verify = "none"
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
                                    sink = ltn12.sink.table(resp),
                                    create = function()
                                      local req_sock = socket.tcp()
                                      req_sock:settimeout(runtime.conf['REQUEST_TIMEOUT'], 't')
                                      return req_sock
                                    end
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
