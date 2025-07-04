package.path = package.path .. ";./?.lua"

local config = require "plugins.crowdsec.config"
local iputils = require "plugins.crowdsec.iputils"
local http = require "resty.http"
local cjson = require "cjson"
local captcha = require "plugins.crowdsec.captcha"
local flag = require "plugins.crowdsec.flag"
local utils = require "plugins.crowdsec.utils"
local ban = require "plugins.crowdsec.ban"
local url = require "plugins.crowdsec.url"
local metrics = require "plugins.crowdsec.metrics"
local live = require "plugins.crowdsec.live"
local stream = require "plugins.crowdsec.stream"
local bit

if _VERSION == "Lua 5.1" then bit = require "bit" else bit = require "bit32" end

local runtime = {}

runtime.timer_started = false -- worker wide variable

local csmod = {}

local DENY = "deny"

local APPSEC_API_KEY_HEADER = "x-crowdsec-appsec-api-key"
local APPSEC_IP_HEADER = "x-crowdsec-appsec-ip"
local APPSEC_HOST_HEADER = "x-crowdsec-appsec-host"
local APPSEC_VERB_HEADER = "x-crowdsec-appsec-verb"
local APPSEC_URI_HEADER = "x-crowdsec-appsec-uri"
local APPSEC_USER_AGENT_HEADER = "x-crowdsec-appsec-user-agent"
local REMEDIATION_API_KEY_HEADER = 'x-api-key'
local METRICS_PERIOD = 900

--- only for debug purpose
--- called only from within the nginx configuration file in the CI
function csmod.debug_metrics()
    METRICS_PERIOD = 15
    ngx.log(ngx.DEBUG, "Shortening metrics period to 15 seconds")
end

function csmod.get_mode()
  return runtime.conf["MODE"]
end

--- return the configuration
local function is_bouncer_enabled()
  if ngx.var.crowdsec_disable_bouncer == "1" then
    return false
  end
  if ngx.var.crowdsec_enable_bouncer == "1" then
    return true
  end
  if runtime.conf["ENABLED"] == "true"  then --- this one is a string
    return true
  end

  return false
end

local function is_appsec_enabled()
  if ngx.var.crowdsec_disable_appsec == "1" then
    return false
  end
  if ngx.var.crowdsec_enable_appsec == "1" then
    return true
  end
  if runtime.conf["APPSEC_ENABLED"] then --- this one is truly a boolean
    return true
  end

  return false
end

local function is_always_send_to_appsec()
  if ngx.var.crowdsec_always_send_to_appsec == "1" then
    return true
  end
  if runtime.conf["ALWAYS_SEND_TO_APPSEC"] then --- this one is truly a boolean
    return true
  end

  return false
end

--- init function
-- init function called by nginx in init_by_lua_block
-- @param configFile path to the configuration file
-- @param userAgent the user agent of the bouncer
-- @return boolean: true if the init is successful, false otherwise
function csmod.init(configFile, userAgent)
  local conf, err = config.loadConfig(configFile, true)
  if conf == nil then
    return nil, err
  end
  local localConf, _ = config.loadConfig(configFile .. ".local", false)
  if localConf ~= nil then
    for k, v in pairs(localConf) do
      conf[k] = v
    end
  end
  runtime.conf = conf
  runtime.userAgent = userAgent
  runtime.cache = ngx.shared.crowdsec_cache
  runtime.fallback = runtime.conf["FALLBACK_REMEDIATION"]

  if runtime.conf["ENABLED"] == "false" then
    return "Disabled", nil
  end

  if runtime.conf["REDIRECT_LOCATION"] == "/" then
    ngx.log(ngx.ERR, "redirect location is set to '/' this will lead into infinite redirection")
  end

  local captcha_ok = true
  local err = captcha.New(runtime.conf["SITE_KEY"], runtime.conf["SECRET_KEY"], runtime.conf["CAPTCHA_TEMPLATE_PATH"], runtime.conf["CAPTCHA_PROVIDER"], runtime.conf["CAPTCHA_RET_CODE"])
  if err ~= nil then
    ngx.log(ngx.ERR, "error loading captcha plugin: " .. err)
    captcha_ok = false
  end
  local succ, err, forcible = runtime.cache:set("captcha_ok", captcha_ok)
  if not succ then
    ngx.log(ngx.ERR, "failed to add captcha state key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end


  local err = ban.new(runtime.conf["BAN_TEMPLATE_PATH"], runtime.conf["REDIRECT_LOCATION"], runtime.conf["RET_CODE"])
  if err ~= nil then
    ngx.log(ngx.ERR, "error loading ban plugins: " .. err)
  end

  if runtime.conf["REDIRECT_LOCATION"] ~= "" then
    table.insert(runtime.conf["EXCLUDE_LOCATION"], runtime.conf["REDIRECT_LOCATION"])
  end

  if runtime.conf["SSL_VERIFY"] == "false" then
    runtime.conf["SSL_VERIFY"] = false
  else
    runtime.conf["SSL_VERIFY"] = true
  end

  local succ, err, forcible = runtime.cache:set("metrics_startup_time", ngx.time())  -- to make sure we have only one thread sending metrics
  if not succ then
    ngx.log(ngx.ERR, "failed to add metrics_startup_time key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end
  local succ, err, forcible = runtime.cache:set("metrics_first_run",true) -- to avoid sending metrics before the first period
  if not succ then
    ngx.log(ngx.ERR, "failed to add metrics_first_run key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  if runtime.conf["ALWAYS_SEND_TO_APPSEC"] == "false" then
    runtime.conf["ALWAYS_SEND_TO_APPSEC"] = false
  else
    runtime.conf["ALWAYS_SEND_TO_APPSEC"] = true
  end

  runtime.conf["APPSEC_ENABLED"] = false

  if runtime.conf["APPSEC_URL"] ~= "" then
    local u = url.parse(runtime.conf["APPSEC_URL"])
    runtime.conf["APPSEC_ENABLED"] = true
    runtime.conf["APPSEC_HOST"] = u.host
    if u.port ~= nil then
      runtime.conf["APPSEC_HOST"] = runtime.conf["APPSEC_HOST"] .. ":" .. u.port
    end
    ngx.log(ngx.ERR, "APPSEC is enabled on '" .. runtime.conf["APPSEC_HOST"] .. "'")
  end


  if runtime.conf["MODE"] == "stream" then
    local succ, err, forcible = runtime.cache:set("startup", true)
    if not succ then
      ngx.log(ngx.ERR, "failed to add startup key in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    local succ, err, forcible = runtime.cache:set("first_run", true)
    if not succ then
      ngx.log(ngx.ERR, "failed to add first_run key in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
  end

  if runtime.conf["API_URL"] == "" and  runtime.conf["APPSEC_URL"] == "" then
    ngx.log(ngx.ERR, "Neither API_URL or APPSEC_URL are defined, remediation component will not do anything")
  end

  if runtime.conf["API_URL"] == "" and  runtime.conf["APPSEC_URL"] ~= "" then
    ngx.log(ngx.ERR, "Only APPSEC_URL is defined, local API decisions will be ignored")
  end



  local tmp =  runtime.conf["API_URL"]:gsub("/+$","")
  if tmp ~= runtime.conf["API_URL"] then
    ngx.log(ngx.DEBUG, "trailing slash in API_URL removed: " .. tmp)
    runtime.conf["API_URL"] = tmp
  end

  if runtime.conf["MODE"] == "live" then
    ngx.log(ngx.INFO, "lua nginx bouncer enabled with live mode")
    live:new()
  else
    ngx.log(ngx.INFO, "lua nginx bouncer enabled with stream mode")
    stream:new()
  end
  return true, nil
end


--- The idea here is to setup the timer that will trigger the metrics sending
--- If first run then just fire the new timer to run the function again in METRICS_PERIOD
--- If not send metrics and run the timer again in METRICS_PERIOD
function csmod.SetupMetrics()
  -- if no API_URL, we don't setup metrics
  if runtime.conf["API_URL"] == "" then
    return
  end

  local function Setup_metrics_timer()
    if ngx.worker.exiting() then
      ngx.log(ngx.INFO, "worker is exiting, not setting up metrics timer")
      return
    end
    local ok, err = ngx.timer.at(METRICS_PERIOD, csmod.SetupMetrics)
    if not ok then
      error("Failed to create the timer: " .. (err or "unknown"))
    else
      ngx.log(ngx.DEBUG, "Metrics timer started in " .. tostring(METRICS_PERIOD) .. " seconds")
    end
  end
  local first_run = runtime.cache:get("metrics_first_run")
  if first_run then
    ngx.log(ngx.DEBUG, "First run for setup metrics ")
    metrics:new(runtime.userAgent)
    runtime.cache:set("metrics_first_run",false)
    Setup_metrics_timer()
    return
  end
  local started = runtime.cache:get("metrics_startup_time")
  if ngx.time() - started >= METRICS_PERIOD then
    if runtime.conf["MODE"] == "stream" then
      stream:refresh_metrics()
    end
    metrics:sendMetrics(
      runtime.conf["API_URL"],
      {['User-Agent']=runtime.userAgent,[REMEDIATION_API_KEY_HEADER]=runtime.conf["API_KEY"],["Content-Type"]="application/json"},
      runtime.conf["SSL_VERIFY"],
      METRICS_PERIOD
    )
    local succ, err, forcible = runtime.cache:set("metrics_startup_time", ngx.time())  -- to make sure we have only one thread sending metrics
    if not succ then
      ngx.log(ngx.ERR, "failed to add metrics_startup_time key in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    --
    --TODO rename the cache key
    Setup_metrics_timer()
  end
end




function csmod.validateCaptcha(captcha_res, remote_ip)
  return captcha.Validate(captcha_res, remote_ip)
end


local function get_body()

  -- the LUA module requires a content-length header to read a body for HTTP 2/3 requests, although it's not mandatory.
  -- This means that we will likely miss body, but AFAIK, there's no workaround for this.
  -- do not even try to read the body if there's no content-length as the LUA API will throw an error
  if ngx.req.http_version() >= 2 and ngx.var.http_content_length == nil then
    ngx.log(ngx.DEBUG, "No content-length header in request")
    return nil
  end
  ngx.req.read_body()
  local body = ngx.req.get_body_data()
  if body == nil then
    local bodyfile = ngx.req.get_body_file()
    if bodyfile then
      local fh, err = io.open(bodyfile, "r")
      if fh then
        body = fh:read("*a")
        fh:close()
      end
    end
  end
  return body
end

function csmod.GetCaptchaBackendKey()
  return captcha.GetCaptchaBackendKey()
end

function csmod.SetupStream()
  local function SetupStreamTimer()
    if ngx.worker.exiting() then
      ngx.log(ngx.INFO, "worker is exiting, not setting up stream timer")
      return
    end
    local last_refresh = stream.cache:get("last_refresh")
    if last_refresh ~= nil then
      if ngx.time() - last_refresh < runtime.conf["UPDATE_FREQUENCY"] then
        ngx.log(ngx.DEBUG, "last refresh was less than " .. runtime.conf["UPDATE_FREQUENCY"] .. " seconds ago, returning")
        local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], SetupStreamTimer)
        if not ok then
          error("Failed to create the timer: " .. (err or "unknown"))
        end
        return
      end
    end
    local refreshing = stream.cache:get("refreshing")
    if not refreshing then
      local err = stream:stream_query(
        runtime.conf["API_URL"],
        runtime.conf["REQUEST_TIMEOUT"],
        REMEDIATION_API_KEY_HEADER,
        runtime.conf["API_KEY"],
        runtime.userAgent,
        runtime.conf["SSL_VERIFY"],
        runtime.conf["BOUNCING_ON_TYPE"]
      )
      if err ~=nil then
        ngx.log(ngx.ERR, "Failed to query the stream: " .. err)
        error("Failed to query the stream: " .. err)
      end
    end
    local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], SetupStreamTimer)
    if not ok then
      error("Failed to create the timer: " .. (err or "unknown"))
    end
  end
  -- if it stream mode and startup start timer
  if runtime.conf["API_URL"] == "" then
    return
  end

  ngx.log(ngx.DEBUG, "running timers: " .. tostring(ngx.timer.running_count()) .. " | pending timers: " .. tostring(ngx.timer.pending_count()))
  local refreshing = stream.cache:get("refreshing")

  if refreshing == true and not ngx.worker.exiting() then
    ngx.log(ngx.DEBUG, "another worker is refreshing the data, returning")
    local ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], SetupStreamTimer)
    if not ok then
      error("Failed to create the timer: " .. (err or "unknown"))
    end
    return
  end


  -- This is done once per worker
  ngx.log(ngx.DEBUG, "timer started: " .. tostring(runtime.timer_started) .. " in worker " .. tostring(ngx.worker.id()))
  if not runtime.timer_started and not ngx.worker.exiting() then
    local ok, err
    ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"],SetupStreamTimer)
    if not ok then
      return true, nil, "Failed to create the timer: " .. (err or "unknown")
    end
    runtime.timer_started = true
    ngx.log(ngx.DEBUG, "Timer launched")
  end
end

---
--- Allow the IP
--- @param ip the IP to check
--- @return boolean: true if the IP is allowed, false otherwise
--- @return string: the remediation to apply
--- @return string: the error message if any
function csmod.allowIp(ip)
  if runtime.conf == nil then
    return true, nil, "Configuration is bad, cannot run properly"
  end

  if runtime.conf["API_URL"] == "" then
    return true, nil, nil
  end

  local key, ip_version = utils.item_to_string(ip, "ip")
  if key == nil then
    return true, nil, "Check failed '" .. ip .. "' has no valid IP address"
  end
  local key_parts = {}
  for i in key.gmatch(key, "([^_]+)") do
    table.insert(key_parts, i)
  end

  metrics:increment("processed", 1,  {ip_type=ip_version})

  local key_type = key_parts[1]
  if key_type == "normal" then
    local decision_string, flag_id = runtime.cache:get("decision_cache/" .. key)
    ngx.log(ngx.DEBUG, "[CACHE] Looking for '" .. key .. "' in cache")
    local  t = utils.split_on_delimiter(decision_string,"/")
    if t == nil then
      return true, nil, "Failed to split decision string"
    end
    ngx.log(ngx.DEBUG, "'" .. key .. "' is in cache")

    local remediation = ""
    if t[2] ~= nil then
      metrics:increment("dropped" ,1, {ip_type=ip_version, origin=t[2]})
    end
    if t[1] ~= nil then
      remediation = t[1]
    end
    return flag_id == 1, remediation, nil
  end

  local ip_network_address = key_parts[3]
  local netmasks = iputils.netmasks_by_key_type[key_type]
  for i, netmask in pairs(netmasks) do
    local item
    if key_type == "ipv4" then
      item = key_type.."_"..netmask.."_"..iputils.ipv4_band(ip_network_address, netmask)
    end
    if key_type == "ipv6" then
      item = key_type.."_"..table.concat(netmask, ":").."_"..iputils.ipv6_band(ip_network_address, netmask)
    end
    local decision_string, flag_id = runtime.cache:get("decision_cache/" .. item)
    ngx.log(ngx.DEBUG, "[CACHE] Looking for '" .. key .. "' in cache")
    if decision_string ~= nil then -- we have it in cache
      if decision_string == "none" then
        ngx.log(ngx.DEBUG, "[CACHE]'" .. key .. "' is in cache with value'" .. decision_string .. "'")
        return true, nil, nil
      end
      ngx.log(ngx.DEBUG, "'" .. key .. "' is in cache with value'" .. decision_string .. "'")
      local  t = utils.split_on_delimiter(decision_string,"/")
      if t == nil then
        return true, nil, "Failed to split decision string"
      end
      local remediation = ""
      if t[2] ~= nil then
        ngx.log(ngx.DEBUG, "'" .. "ipversion: " .. ip_version .. " origin: " .. t[2] .. "' is counted")
        metrics:increment("dropped", 1, {ip_type=ip_version, origin=t[2]}) -- origin: at this point we are pretty sure there's one
        -- and that the decision is a blocking
      end
      if t[1] ~= nil then
        remediation = t[1] -- remediation
      end
      -- flag_id is 1 if the decision is a not blocking one
      return flag_id == 1, remediation, nil
    end
  end

  -- if live mode, query lapi
  if runtime.conf["MODE"] == "live" then
    ngx.log(ngx.DEBUG, "live mode")
    local ok, remediation, origin, err = live:live_query(
      ip,
      runtime.conf["API_URL"],
      runtime.conf["REQUEST_TIMEOUT"],
      runtime.conf["CACHE_EXPIRATION"],
      REMEDIATION_API_KEY_HEADER,
      runtime.conf['API_KEY'],
      runtime.userAgent,
      runtime.conf["SSL_VERIFY"],
      runtime.conf["BOUNCING_ON_TYPE"]
    )
    -- debug: wip
    ngx.log(ngx.DEBUG, "live_query: " .. ip .. " | " .. (ok and "not banned with" or "banned with") .. " | " .. tostring(remediation) .. " | " .. tostring(origin) .. " | " .. tostring(err))
    local _, is_ipv4 = iputils.parseIPAddress(ip)
    if is_ipv4 then
      ip_version = "ipv4"
    else
      ip_version = "ipv6"
    end

    if remediation ~= nil and remediation == "ban" then
      metrics:increment("dropped", 1, {ip_type=ip_version, origin=origin} )
    return ok, remediation, err
    end
  end
  return true, nil, nil
end

function csmod.AppSecCheck(ip)
  local httpc = http.new()
  httpc:set_timeouts(runtime.conf["APPSEC_CONNECT_TIMEOUT"], runtime.conf["APPSEC_SEND_TIMEOUT"], runtime.conf["APPSEC_PROCESS_TIMEOUT"])

  local uri = ngx.var.request_uri
  local headers = ngx.req.get_headers()

  -- overwrite headers with crowdsec appsec require headers
  headers[APPSEC_IP_HEADER] = ip
  headers[APPSEC_HOST_HEADER] = ngx.var.http_host
  headers[APPSEC_VERB_HEADER] = ngx.var.request_method
  headers[APPSEC_URI_HEADER] = uri
  headers[APPSEC_USER_AGENT_HEADER] = ngx.var.http_user_agent
  headers[APPSEC_API_KEY_HEADER] = runtime.conf["API_KEY"]

  -- set CrowdSec APPSEC Host
  headers["host"] = runtime.conf["APPSEC_HOST"]

  local ok, remediation, status_code = true, "allow", 200
  if runtime.conf["APPSEC_FAILURE_ACTION"] == DENY then
    ok = false
    remediation = runtime.conf["FALLBACK_REMEDIATION"]
  end

  local method = "GET"

  local body = get_body()
  if body ~= nil then
    if #body > 0 then
      method = "POST"
      if headers["content-length"] == nil then
        headers["content-length"] = tostring(#body)
      end
    end
  else
    headers["content-length"] = nil
  end

  local res, err = httpc:request_uri(runtime.conf["APPSEC_URL"], {
    method = method,
    headers = headers,
    body = body,
    ssl_verify = runtime.conf["SSL_VERIFY"],
  })
  httpc:close()

  if err ~= nil then
    ngx.log(ngx.ERR, "Fallback because of err: " .. err)
    return ok, remediation, status_code, err
  end

  if res.status == 200 then
    ok = true
    remediation = "allow"
  elseif res.status == 403 then
    ok = false
    ngx.log(ngx.DEBUG, "Appsec body response: " .. res.body)
    local response = cjson.decode(res.body)
    remediation = response.action
    if response.http_status ~= nil then
      ngx.log(ngx.DEBUG, "Got status code from APPSEC: " .. response.http_status)
      status_code = response.http_status
    else
      status_code = ngx.HTTP_FORBIDDEN
    end
  elseif res.status == 401 then
    ngx.log(ngx.ERR, "Unauthenticated request to APPSEC")
  else
    ngx.log(ngx.ERR, "Bad request to APPSEC (" .. res.status .. "): " .. res.body)
  end

  return ok, remediation, status_code, err

end

--- return if the IP is allowed or not
-- return if the IP is allowed, false otherwise
-- the function is called from nginx access_by_lua_block
-- @param ip the IP to check
function csmod.Allow(ip)
  local remediationSource = flag.BOUNCER_SOURCE
  local ret_code = nil
  local remediation = ""
  local ok = true
  local err = ""
  if runtime.conf["ENABLED"] ~= "false" then

    if runtime.conf["ENABLE_INTERNAL"] == "false" and ngx.req.is_internal() then
      ngx.exit(ngx.DECLINED)
    end

    if utils.table_len(runtime.conf["EXCLUDE_LOCATION"]) > 0 then
      for k, v in pairs(runtime.conf["EXCLUDE_LOCATION"]) do
        if ngx.var.uri == v then
          ngx.log(ngx.ERR, "whitelisted location: " .. v)
          ngx.exit(ngx.DECLINED)
        end
        local uri_to_check = v
        if utils.ends_with(uri_to_check, "/") == false then
          uri_to_check = uri_to_check .. "/"
        end
        if utils.starts_with(ngx.var.uri, uri_to_check) then
          ngx.log(ngx.ERR, "whitelisted location: " .. uri_to_check)
        end
      end
    end

    if not is_bouncer_enabled()  then
      ngx.log(ngx.ERR, "bouncer disabled by user")
      ngx.exit(ngx.DECLINED)
    end

    ok, remediation, err = csmod.allowIp(ip)
    if err ~= nil then
      ngx.log(ngx.ERR, "[Crowdsec] bouncer error: " .. err)
    end

    -- if the ip is now allowed, try to delete its captcha state in cache
    if ok == true then
      ngx.shared.crowdsec_cache:delete("captcha_" .. ip)
    end
  end
  -- check with appSec if the remediation component doesn't have decisions for the IP
  -- OR
  -- that user configured the remediation component to always check on the appSec (even if there is a decision for the IP)
  if is_appsec_enabled() and (ok == true or is_always_send_to_appsec())  then
    local appsecOk, appsecRemediation, status_code, err = csmod.AppSecCheck(ip)
    if err ~= nil then
      ngx.log(ngx.ERR, "AppSec check: " .. err)
    end
    if appsecOk == false then
      ok = false
      remediationSource = flag.APPSEC_SOURCE
      remediation = appsecRemediation
      ret_code = status_code
    end
  end

  local captcha_ok = runtime.cache:get("captcha_ok")

  if runtime.fallback ~= "" then
    -- if we can't use captcha, fallback
    if remediation == "captcha" and captcha_ok == false then
      remediation = runtime.fallback
    end

    -- if remediation is not supported, fallback
    if remediation ~= "captcha" and remediation ~= "ban" then
      remediation = runtime.fallback
    end
  end

  if captcha_ok then -- if captcha can be use (configuration is valid)
    -- we check if the IP need to validate its captcha before checking it against crowdsec local API
    local previous_uri, flags = ngx.shared.crowdsec_cache:get("captcha_"..ip)
    local source, state_id, err = flag.GetFlags(flags)
    local body = get_body()

    -- nil body means it was likely not a post, abort here because the user hasn't provided a captcha solution

    if previous_uri ~= nil and state_id == flag.VERIFY_STATE and body ~= nil then
        local captcha_res = ngx.req.get_post_args()[csmod.GetCaptchaBackendKey()] or 0
        if captcha_res ~= 0 then
            local valid, err = csmod.validateCaptcha(captcha_res, ip)
            if err ~= nil then
              ngx.log(ngx.ERR, "Error while validating captcha: " .. err)
            end
            if valid == true then
                -- if the captcha is valid and has been applied by the application security component
                -- then we delete the state from the cache because from the bouncing part, if the user solve the captcha
                -- we will not propose a captcha until the 'CAPTCHA_EXPIRATION'.
                -- But for the Application security component, we serve the captcha each time the user trigger it.
                if source == flag.APPSEC_SOURCE then
                  ngx.shared.crowdsec_cache:delete("captcha_"..ip)
                else
                  local succ, err, forcible = ngx.shared.crowdsec_cache:set("captcha_"..ip, previous_uri, runtime.conf["CAPTCHA_EXPIRATION"], bit.bor(flag.VALIDATED_STATE, source) )
                  if not succ then
                    ngx.log(ngx.ERR, "failed to add key about captcha for ip '" .. ip .. "' in cache: "..err)
                  end
                  if forcible then
                    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
                  end
                end
                -- captcha is valid, we redirect the IP to its previous URI but in GET method
                ngx.req.set_method(ngx.HTTP_GET)
                return ngx.redirect(previous_uri)
            else
                ngx.log(ngx.ALERT, "Invalid captcha from " .. ip)
            end
        end
    end
  end
  if not ok then
      if remediation == "ban" then
        ngx.log(ngx.ALERT, "[Crowdsec] denied '" .. ip .. "' with '"..remediation.."' (by " .. flag.Flags[remediationSource] .. ")")
        ban.apply(ret_code)
        return
      end
      -- if the remediation is a captcha and captcha is well configured
      if remediation == "captcha" and captcha_ok and ngx.var.uri ~= "/favicon.ico" then
          local previous_uri, flags = ngx.shared.crowdsec_cache:get("captcha_"..ip)
          local source, state_id, err = flag.GetFlags(flags)
          -- we check if the IP is already in cache for captcha and not yet validated
          if previous_uri == nil or state_id ~= flag.VALIDATED_STATE or remediationSource == flag.APPSEC_SOURCE then 
              local uri = ngx.var.uri
              -- in case its not a GET request, we prefer to fallback on referer
              if ngx.req.get_method() ~= "GET" then
                local headers, err = ngx.req.get_headers()
                for k, v in pairs(headers) do
                  if k == "referer" then
                    uri = v
                  end
                end
              end
              local succ, err, forcible = ngx.shared.crowdsec_cache:set("captcha_"..ip, uri , 60, bit.bor(flag.VERIFY_STATE, remediationSource))
              if not succ then
                ngx.log(ngx.ERR, "failed to add key about captcha for ip '" .. ip .. "' in cache: "..err)
              end
              if forcible then
                ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
              end
              ngx.log(ngx.ALERT, "[Crowdsec] denied '" .. ip .. "' with '"..remediation.."'")
              captcha.apply()
              return
          end
      end
  end
  ngx.exit(ngx.DECLINED)
end



-- Use it if you are able to close at shuttime
function csmod.close()
end

return csmod
