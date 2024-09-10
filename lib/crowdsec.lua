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

-- contain runtime = {}
local runtime = {}
-- remediations are stored in cache as int (shared dict tags)
-- we need to translate IDs to text with this.
runtime.remediations = {}
runtime.remediations["1"] = "ban"
runtime.remediations["2"] = "captcha"

-- origins are stored in cache as int (shared dict tags)
-- with the same tag as remediations but on the 5th
runtime.origins = {}
runtime.origins["0"] = "CAPI"
runtime.origins["1"] = "LAPI"
runtime.origins["2"] = "cscli"
runtime.origins["3"] = "unknown"



local csmod = {}

local PASSTHROUGH = "passthrough"
local DENY = "deny"

local APPSEC_API_KEY_HEADER = "x-crowdsec-appsec-api-key"
local APPSEC_IP_HEADER = "x-crowdsec-appsec-ip"
local APPSEC_HOST_HEADER = "x-crowdsec-appsec-host"
local APPSEC_VERB_HEADER = "x-crowdsec-appsec-verb"
local APPSEC_URI_HEADER = "x-crowdsec-appsec-uri"
local APPSEC_USER_AGENT_HEADER = "x-crowdsec-appsec-user-agent"
local REMEDIATION_API_KEY_HEADER = 'x-api-key'


--- init function
-- init function called by nginx in init_by_lua_block
-- @param configFile path to the configuration file
-- @param userAgent the user agent of the bouncer
-- @return boolean: true if the init is successful, false otherwise
function csmod.init(configFile, userAgent)
  local conf, err = config.loadConfig(configFile)
  if conf == nil then
    return nil, err
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
  local err = captcha.New(runtime.conf["SITE_KEY"], runtime.conf["SECRET_KEY"], runtime.conf["CAPTCHA_TEMPLATE_PATH"], runtime.conf["CAPTCHA_PROVIDER"])
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

  if runtime.conf["METRICS_PERIOD"] == "" or runtime.conf["METRICS_PERIOD"] == nil then
    runtime.conf["METRICS_PERIOD"] = 300
  end

  runtime.cache:set("metrics_startup_time", ngx.time())  -- to make sure we have only one thread sending metrics
  runtime.cache:set("metrics_first_run",true) -- to avoid sending metrics before the first period

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

  if runtime.conf["MODE"] == "live" then
    live:new(runtime.conf["API_URL"], runtime.conf["CACHE_EXPIRATION"], runtime.conf["BOUNCING_ON_TYPE"])
  end
  return true, nil
end


local function Setup_metrics()
  local function Setup_metrics_timer()
    local ok, err = ngx.timer.at(runtime.conf["METRICS_PERIOD"], Setup_metrics)
    if not ok then
      error("Failed to create the timer: " .. (err or "unknown"))
    else
      ngx.log(ngx.ERR, "Metrics timer started in " .. tostring(runtime.conf["METRICS_PERIOD"]) .. " seconds")
    end
  end
  local first_run = runtime.cache:get("metrics_first_run")
  if first_run then
    ngx.log(ngx.INFO, "First run for setup metrics ") --debug
    metrics:new(runtime.userAgent)
    runtime.cache:set("metrics_first_run",false)
    Setup_metrics_timer()
    return
  end
  local started = runtime.cache:get("metrics_startup_time")
  if ngx.time() - started >= runtime.conf["METRICS_PERIOD"] then
    metrics:sendMetrics(runtime.conf["API_URL"],{['User-Agent']=runtime.userAgent,[REMEDIATION_API_KEY_HEADER]=runtime.conf["API_KEY"]},runtime.conf["SSL_VERIFY"], runtime.conf["METRICS_PERIOD"])
    runtime.cache:set("metrics_startup_time",ngx.time()) --TODO add err handling
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

function csmod.GetCaptchaTemplate()
  return captcha.GetTemplate()
end

function csmod.GetCaptchaBackendKey()
  return captcha.GetCaptchaBackendKey()
end

function csmod.SetupStream()
  -- if it stream mode and startup start timer
  if runtime.conf["API_URL"] == "" then
    return
  end
  ngx.log(ngx.DEBUG, "timer started: " .. tostring(runtime.timer_started) .. " in worker " .. tostring(ngx.worker.id()))
  if runtime.timer_started == false and runtime.conf["MODE"] == "stream" then
    local ok, err
    ok, err = ngx.timer.at(runtime.conf["UPDATE_FREQUENCY"], stream:stream_query())
    if not ok then
      return true, nil, "Failed to create the timer: " .. (err or "unknown")
    end
    runtime.timer_started = true
    ngx.log(ngx.DEBUG, "Timer launched")
  end
end

---
function csmod.allowIp(ip)
  if runtime.conf == nil then
    return true, nil, "Configuration is bad, cannot run properly"
  end

  if runtime.conf["API_URL"] == "" then
    return true, nil, nil
  end
  csmod.SetupStream()
  metrics:increment("processed",1)

  local key = utils.item_to_string(ip, "ip")
  if key == nil then
    return true, nil, "Check failed '" .. ip .. "' has no valid IP address"
  end
  local key_parts = {}
  for i in key.gmatch(key, "([^_]+)") do
    table.insert(key_parts, i)
  end

  local key_type = key_parts[1]
  if key_type == "normal" then
    local decision_string, flag_id = runtime.cache:get(key)
    local  remediation, origin = utils.split_on_first_slash(decision_string)
    metrics:increment(origin,1)
    if decision_string ~= nil then -- we have it in cache
      ngx.log(ngx.DEBUG, "'" .. key .. "' is in cache")
      return flag_id == 1, remediation, nil
    end
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
    local decision_string, flag_id = runtime.cache:get(item)
    if decision_string ~= nil then -- we have it in cache
      ngx.log(ngx.DEBUG, "'" .. key .. "' is in cache")
      ngx.log(ngx.INFO, "'" .. key .. "' is in cache")
      local  remediation, origin = utils.split_on_delimiter(decision_string,"/")
      metrics:increment(origin,1)
      return flag_id == 1, remediation, nil
    end
  end

  -- if live mode, query lapi
  if runtime.conf["MODE"] == "live" then
    local ok, remediation, origin, err = live:live_query(ip, runtime.conf['API_KEY'])
    -- debug: wip
    ngx.log(ngx.DEBUG, "live_query: " .. ip .. " | " .. (ok == false and "banned with" or not "banned with") .. " | " .. tostring(remediation) .. " | " .. tostring(origin) .. " | " .. tostring(err))
    if remediation ~= nil then
      metrics:increment(origin,1)
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
  if runtime.conf["ENABLED"] == "false" then
    ngx.exit(ngx.DECLINED)
  end

  if ngx.req.is_internal() then
    ngx.exit(ngx.DECLINED)
  end


  Setup_metrics()

  local remediationSource = flag.BOUNCER_SOURCE
  local ret_code = nil



  if utils.table_len(runtime.conf["EXCLUDE_LOCATION"]) > 0 then
    for k, v in pairs(runtime.conf["EXCLUDE_LOCATION"]) do
      if ngx.var.uri == v then
        ngx.log(ngx.ERR,  "whitelisted location: " .. v)
        ngx.exit(ngx.DECLINED)
      end
      local uri_to_check = v
      if utils.ends_with(uri_to_check, "/") == false then
        uri_to_check = uri_to_check .. "/"
      end
      if utils.starts_with(ngx.var.uri, uri_to_check) then
        ngx.log(ngx.ERR,  "whitelisted location: " .. uri_to_check)
      end
    end
  end

  local ok, remediation, err = csmod.allowIp(ip)
  if err ~= nil then
    ngx.log(ngx.ERR, "[Crowdsec] bouncer error: " .. err)
  end

  -- if the ip is now allowed, try to delete its captcha state in cache
  if ok == true then
    ngx.shared.crowdsec_cache:delete("captcha_" .. ip)
  end

  -- check with appSec if the remediation component doesn't have decisions for the IP
  -- OR
  -- that user configured the remediation component to always check on the appSec (even if there is a decision for the IP)
  if ok == true or runtime.conf["ALWAYS_SEND_TO_APPSEC"] == true then
    if runtime.conf["APPSEC_ENABLED"] == true and ngx.var.no_appsec ~= "1" then
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
              ngx.header.content_type = "text/html"
              ngx.header.cache_control = "no-cache"
              ngx.say(csmod.GetCaptchaTemplate())
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
