local http = require "resty.http"
local cjson = require "cjson"
local template = require "plugins.crowdsec.template"
local utils = require "plugins.crowdsec.utils"

local M = {_TYPE='module', _NAME='recaptcha.funcs', _VERSION='1.0-0'}

local captcha_backend_url = {}
captcha_backend_url["recaptcha"] = "https://www.recaptcha.net/recaptcha/api/siteverify"
captcha_backend_url["hcaptcha"] = "https://hcaptcha.com/siteverify"
captcha_backend_url["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
-- cap is self-hosted, so its verify URL is built from the configured endpoint in M.New()

local captcha_frontend_js = {}
captcha_frontend_js["recaptcha"] = "https://www.recaptcha.net/recaptcha/api.js"
captcha_frontend_js["hcaptcha"] = "https://js.hcaptcha.com/1/api.js"
captcha_frontend_js["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/api.js"
-- cap-widget is still pre-1.0, so pin the version rather than tracking the latest tag
captcha_frontend_js["cap"] = "https://cdn.jsdelivr.net/npm/cap-widget@0.1.56"

local captcha_frontend_key = {}
captcha_frontend_key["recaptcha"] = "g-recaptcha"
captcha_frontend_key["hcaptcha"] = "h-captcha"
captcha_frontend_key["turnstile"] = "cf-turnstile"
-- yields the "cap-response" form field name via M.GetCaptchaBackendKey()
captcha_frontend_key["cap"] = "cap"

M.SecretKey = ""
M.SiteKey = ""
M.Template = ""
M.ret_code = ngx.HTTP_OK
M.SSLVerify = true

function M.New(siteKey, secretKey, TemplateFilePath, captcha_provider, ret_code, api_endpoint, verify_endpoint, ssl_verify)

    if siteKey == nil or siteKey == "" then
      return "no recaptcha site key provided, can't use recaptcha"
    end
    M.SiteKey = siteKey

    if secretKey == nil or secretKey == "" then
      return "no recaptcha secret key provided, can't use recaptcha"
    end

    M.SecretKey = secretKey

    if TemplateFilePath == nil then
      return "CAPTCHA_TEMPLATE_PATH variable is empty, will ban without template"
    end
    if utils.file_exist(TemplateFilePath) == false then
      return "captcha template file doesn't exist, can't use recaptcha"
    end

    local captcha_template = utils.read_file(TemplateFilePath)
    if captcha_template == nil then
        return "Template file " .. TemplateFilePath .. "not found."
    end

    M.CaptchaProvider = captcha_provider

    -- New() runs before crowdsec.lua turns SSL_VERIFY into a boolean, so the raw
    -- config string arrives here and "false" would be truthy in Lua. Normalize both
    -- shapes, and only ever opt out on an explicit false.
    M.SSLVerify = not (ssl_verify == false or ssl_verify == "false")

    -- the provider drives every lookup below, so reject an unknown one here rather
    -- than letting it surface as a nil concatenation while rendering the template
    if captcha_frontend_key[M.CaptchaProvider] == nil then
        return "unsupported captcha provider '" .. tostring(captcha_provider) .. "'"
    end

    -- cap is self-hosted, so every URL derives from the operator's own instance.
    -- The browser and the bouncer can reach that instance on different addresses,
    -- so verification may target a private endpoint while the widget uses the public one.
    if M.CaptchaProvider == "cap" then
        if api_endpoint == nil or api_endpoint == "" then
            return "CAPTCHA_API_ENDPOINT is required when CAPTCHA_PROVIDER is 'cap'"
        end
        local public_base = api_endpoint:gsub("/+$", "")
        local verify_base = public_base
        if verify_endpoint ~= nil and verify_endpoint ~= "" then
            verify_base = verify_endpoint:gsub("/+$", "")
        end
        M.ApiEndpoint = public_base .. "/" .. M.SiteKey .. "/"
        captcha_backend_url["cap"] = verify_base .. "/" .. M.SiteKey .. "/siteverify"
    end

    local ret_code_ok = false
    if ret_code ~= nil and ret_code ~= 0 and ret_code ~= "" then
        for k, v in pairs(utils.HTTP_CODE) do
            if k == ret_code then
                M.ret_code = utils.HTTP_CODE[ret_code]
                ret_code_ok = true
                break
            end
        end
        if ret_code_ok == false then
            ngx.log(ngx.ERR, "CAPTCHA_RET_CODE '" .. ret_code .. "' is not supported, using default HTTP code " .. M.ret_code)
        end
    end

    local template_data = {}
    -- still exported so templates written against the previous layout keep rendering
    template_data["captcha_site_key"] =  M.SiteKey
    template_data["captcha_frontend_js"] = captcha_frontend_js[M.CaptchaProvider]
    template_data["captcha_frontend_key"] = captcha_frontend_key[M.CaptchaProvider]

    -- providers disagree on how the widget is loaded and declared, and the template
    -- engine has no conditionals, so the markup is rendered here and injected whole
    if M.CaptchaProvider == "cap" then
        template_data["captcha_frontend_js_tag"] =
            '<script type="module" src="' .. captcha_frontend_js["cap"] .. '"></script>'
        -- the widget injects its own hidden input, named so that it matches
        -- M.GetCaptchaBackendKey() instead of cap's "cap-token" default
        template_data["captcha_widget"] =
            '<cap-widget id="captcha" data-cap-api-endpoint="' .. M.ApiEndpoint ..
            '" data-cap-hidden-field-name="' .. M.GetCaptchaBackendKey() .. '"></cap-widget>' ..
            -- wrapped in a function so captchaCallback resolves when the event fires
            -- rather than while this script is parsed: it is declared further down
            '<script>document.getElementById("captcha")' ..
            '.addEventListener("solve", function () { captchaCallback() })</script>'
    else
        template_data["captcha_frontend_js_tag"] =
            '<script src="' .. captcha_frontend_js[M.CaptchaProvider] .. '" async defer></script>'
        template_data["captcha_widget"] =
            '<div id="captcha" class="' .. captcha_frontend_key[M.CaptchaProvider] ..
            '" data-sitekey="' .. M.SiteKey .. '" data-callback="captchaCallback"></div>'
    end

    local view = template.compile(captcha_template, template_data)
    M.Template = view

    return nil
end

function M.apply()
    ngx.header.content_type = "text/html"
    ngx.header.cache_control = "no-cache"
    ngx.status = M.ret_code
    ngx.say(M.Template)
    ngx.exit(M.ret_code)
end

function M.GetCaptchaBackendKey()
    return captcha_frontend_key[M.CaptchaProvider] .. "-response"
end

function table_to_encoded_url(args)
    local params = {}
    for k, v in pairs(args) do table.insert(params, k .. '=' .. v) end
    return table.concat(params, "&")
end

-- cap is reCAPTCHA-shaped but not reCAPTCHA-compatible: it takes a JSON body and
-- reports failures as a plain "error" string rather than an "error-codes" array,
-- so it gets its own request path instead of branching through the one below.
function M.ValidateCap(captcha_res, remote_ip)
    local body = cjson.encode({
        secret   = M.SecretKey,
        response = captcha_res
    })

    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(captcha_backend_url["cap"], {
      method = "POST",
      body = body,
      headers = {
          ["Content-Type"] = "application/json",
          -- verification is server-to-server, so the connecting address is the
          -- bouncer's own. Forward the address that actually solved the challenge
          -- so the cap instance (or a proxy in front of it) logs and rate limits
          -- against the client rather than against nginx.
          ["X-Real-IP"] = remote_ip,
      },
      -- a self-hosted instance is commonly reached over TLS it terminates itself,
      -- so honor SSL_VERIFY here the way the LAPI and appsec calls already do.
      -- Only cap gets this: the hosted providers present publicly trusted certs,
      -- and skipping verification against them would be a downgrade for no gain.
      ssl_verify = M.SSLVerify,
    })
    httpc:close()

    -- Every path below fails closed: anything short of cap explicitly answering
    -- "success" leaves the visitor on the captcha page to try again. The instance
    -- is self-hosted and rate limited per client, so a visitor can provoke these
    -- failures for themselves on demand; treating them as a solve would hand out
    -- CAPTCHA_EXPIRATION worth of access for a token nothing ever verified.
    if err ~= nil then
      return false, err
    end

    -- a self-hosted instance can sit behind a proxy that answers with an HTML error
    -- page, so a failed decode must not raise out of the access phase
    local ok, result = pcall(cjson.decode, res.body)
    if not ok or type(result) ~= "table" then
      return false, "cap returned a non-JSON response (HTTP " .. tostring(res.status) .. ")"
    end

    -- separated from the decode failure above so an outage or a tripped rate limit
    -- is distinguishable in the logs from a visitor submitting a bad token
    if res.status ~= ngx.HTTP_OK then
      return false, "cap verification failed with HTTP " .. tostring(res.status) ..
                    " (" .. tostring(result.error) .. ")"
    end

    if result.success ~= true and result.error ~= nil then
      ngx.log(ngx.ERR, "cap captcha validation failed: " .. tostring(result.error))
    end

    return result.success == true, nil
end

function M.Validate(captcha_res, remote_ip)
    if M.CaptchaProvider == "cap" then
      -- cap has no remoteip body field, so the IP travels as an X-Real-IP header.
      -- Note this path fails closed, unlike the hosted providers below: their
      -- endpoints are not something a visitor can knock over to skip the captcha.
      return M.ValidateCap(captcha_res, remote_ip)
    end

    local body = {
        secret   = M.SecretKey,
        response = captcha_res,
        remoteip = remote_ip
    }

    local data = table_to_encoded_url(body)
    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(captcha_backend_url[M.CaptchaProvider], {
      method = "POST",
      body = data,
      headers = {
          ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    httpc:close()
    if err ~= nil then
      return true, err
    end

    local result = cjson.decode(res.body)

    if result.success == false then
      for k, v in pairs(result["error-codes"]) do
        if v == "invalid-input-secret" then
          ngx.log(ngx.ERR, "reCaptcha secret key is invalid")
          return true, nil
        end
      end 
    end

    return result.success, nil
end


return M
