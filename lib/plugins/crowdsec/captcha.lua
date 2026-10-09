local http = require "resty.http"
local cjson = require "cjson"
local template = require "plugins.crowdsec.template"
local utils = require "plugins.crowdsec.utils"

local M = {_TYPE='module', _NAME='recaptcha.funcs', _VERSION='1.0-0'}

local captcha_backend_url = {}
captcha_backend_url["recaptcha"] = "https://www.recaptcha.net/recaptcha/api/siteverify"
captcha_backend_url["hcaptcha"] = "https://hcaptcha.com/siteverify"
captcha_backend_url["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
-- cap: self-hosted proof-of-work captcha (https://capjs.js.org)
-- The verify URL is configurable via CAPTCHA_VERIFY_URL (defaults to http://localhost:3000/api/validate)
captcha_backend_url["cap"] = nil -- set dynamically in New() from CAPTCHA_VERIFY_URL

local captcha_frontend_js = {}
captcha_frontend_js["recaptcha"] = "https://www.recaptcha.net/recaptcha/api.js"
captcha_frontend_js["hcaptcha"] = "https://js.hcaptcha.com/1/api.js"
captcha_frontend_js["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/api.js"
-- cap: widget JS URL is configurable via CAPTCHA_JS_URL (defaults to http://localhost:3000/cap.js)
captcha_frontend_js["cap"] = nil -- set dynamically in New() from CAPTCHA_JS_URL

local captcha_frontend_key = {}
captcha_frontend_key["recaptcha"] = "g-recaptcha"
captcha_frontend_key["hcaptcha"] = "h-captcha"
captcha_frontend_key["turnstile"] = "cf-turnstile"
captcha_frontend_key["cap"] = "cap"

M.SecretKey = ""
M.SiteKey = ""
M.Template = ""
M.ret_code = ngx.HTTP_OK

function M.New(siteKey, secretKey, TemplateFilePath, captcha_provider, ret_code, captcha_verify_url, captcha_js_url)

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

    -- For the cap provider, the backend URL and frontend JS URL are configurable
    -- because Cap is self-hosted. We read them from the runtime config passed via
    -- the extra parameters, falling back to the canonical defaults.
    if captcha_provider == "cap" then
        captcha_backend_url["cap"] = (captcha_verify_url ~= nil and captcha_verify_url ~= "") and captcha_verify_url or "http://localhost:3000/api/validate"
        captcha_frontend_js["cap"] = (captcha_js_url     ~= nil and captcha_js_url     ~= "") and captcha_js_url     or "http://localhost:3000/cap.js"
    end

    local template_data = {}
    template_data["captcha_site_key"] =  M.SiteKey
    template_data["captcha_frontend_js"] = captcha_frontend_js[M.CaptchaProvider]
    template_data["captcha_frontend_key"] = captcha_frontend_key[M.CaptchaProvider]
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

local function table_to_encoded_url(args)
    local params = {}
    for k, v in pairs(args) do table.insert(params, k .. '=' .. v) end
    return table.concat(params, "&")
end

function M.Validate(captcha_res, remote_ip)
    -- Cap uses a JSON POST to a self-hosted server instead of form-encoded POST
    -- to a third-party API, so it needs its own request path.
    if M.CaptchaProvider == "cap" then
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

-- Cap validation: POST JSON { token, secret } to the self-hosted Cap server.
-- The Cap server responds with { "success": true } or { "success": false }.
function M.ValidateCap(captcha_res, remote_ip)
    local payload = cjson.encode({
        token    = captcha_res,
        secret   = M.SecretKey,
        remoteip = remote_ip,
    })

    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(captcha_backend_url["cap"], {
        method = "POST",
        body   = payload,
        headers = {
            ["Content-Type"] = "application/json",
        },
    })
    httpc:close()

    if err ~= nil then
        return true, err
    end

    local result = cjson.decode(res.body)
    return result.success, nil
end


return M
