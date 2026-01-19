local http = require "resty.http"
local cjson = require "cjson"
local template = require "plugins.crowdsec.template"
local utils = require "plugins.crowdsec.utils"

---@class CaptchaModule
---@field SecretKey string
---@field SiteKey string
---@field CaptchaProvider string
---@field compiled_template CompiledTemplate?
---@field static_vars table<string, string>
---@field ret_code number
---@field New fun(siteKey: string?, secretKey: string?, TemplateFilePath: string?, captcha_provider: string?, ret_code: number?): string?
---@field apply fun()
---@field GetCaptchaBackendKey fun(): string
---@field Validate fun(captcha_res: string, remote_ip: string): boolean, string?
local M = {_TYPE='module', _NAME='recaptcha.funcs', _VERSION='1.0-0'}

---@type table<string, string>
local captcha_backend_url = {
    ["recaptcha"] = "https://www.recaptcha.net/recaptcha/api/siteverify",
    ["hcaptcha"] = "https://hcaptcha.com/siteverify",
    ["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
}

---@type table<string, string>
local captcha_frontend_js = {
    ["recaptcha"] = "https://www.recaptcha.net/recaptcha/api.js",
    ["hcaptcha"] = "https://js.hcaptcha.com/1/api.js",
    ["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/api.js"
}

---@type table<string, string>
local captcha_frontend_key = {
    ["recaptcha"] = "g-recaptcha",
    ["hcaptcha"] = "h-captcha",
    ["turnstile"] = "cf-turnstile"
}

M.SecretKey = ""
M.SiteKey = ""
M.CaptchaProvider = ""
M.compiled_template = nil
M.static_vars = {}
M.ret_code = ngx.HTTP_OK

--- Initialize the captcha module
---@param siteKey string? Public site key from captcha provider
---@param secretKey string? Secret key from captcha provider
---@param TemplateFilePath string? Path to the captcha template file
---@param captcha_provider string? Provider name (recaptcha, hcaptcha, turnstile)
---@param ret_code number? HTTP status code to return
---@return string? error Error message if initialization failed
function M.New(siteKey, secretKey, TemplateFilePath, captcha_provider, ret_code)

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

    M.CaptchaProvider = captcha_provider or "recaptcha"

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

    -- Store static captcha variables
    M.static_vars = {
        captcha_site_key = M.SiteKey,
        captcha_frontend_js = captcha_frontend_js[M.CaptchaProvider],
        captcha_frontend_key = captcha_frontend_key[M.CaptchaProvider]
    }

    -- Precompile template at init time
    M.compiled_template = template.precompile(captcha_template)
    if M.compiled_template ~= nil then
        ngx.log(ngx.DEBUG, "Captcha template precompiled successfully")
    end

    return nil
end

--- Apply the captcha remediation (show captcha page)
function M.apply()
    ngx.header.content_type = "text/html"
    ngx.header.cache_control = "no-cache"
    ngx.status = M.ret_code

    if M.compiled_template ~= nil then
        -- Use shared helper, pass static captcha vars as extras
        local template_vars = template.get_request_vars(M.static_vars)
        local rendered = template.render(M.compiled_template, template_vars)
        ngx.say(rendered)
    end

    ngx.exit(M.ret_code)
end

--- Get the form field name for the captcha response
---@return string key The form field name
function M.GetCaptchaBackendKey()
    return captcha_frontend_key[M.CaptchaProvider] .. "-response"
end

--- Convert a table to URL-encoded form data
---@param args table<string, string>
---@return string encoded URL-encoded string
local function table_to_encoded_url(args)
    local params = {}
    for k, v in pairs(args) do
        table.insert(params, k .. '=' .. v)
    end
    return table.concat(params, "&")
end

--- Validate a captcha response with the provider
---@param captcha_res string The captcha response token from the form
---@param remote_ip string The client's IP address
---@return boolean success Whether the captcha was valid
---@return string? error Error message if validation failed
function M.Validate(captcha_res, remote_ip)
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
