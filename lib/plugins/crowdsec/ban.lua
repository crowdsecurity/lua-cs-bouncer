local utils = require "plugins.crowdsec.utils"
local template = require "plugins.crowdsec.template"

---@class BanModule
---@field compiled_template CompiledTemplate?
---@field redirect_location string
---@field ret_code number
---@field new fun(template_path: string?, redirect_location: string?, ret_code: number?): string?
---@field apply fun(ret_code?: number, extra_vars?: table<string, string>)
local M = {_TYPE='module', _NAME='ban.funcs', _VERSION='1.0-0'}

M.compiled_template = nil
M.redirect_location = ""
M.ret_code = ngx.HTTP_FORBIDDEN

--- Initialize the ban module
---@param template_path string? Path to the ban template file
---@param redirect_location string? URL to redirect to instead of showing template
---@param ret_code number? HTTP status code to return
---@return string? error Error message if initialization failed
function M.new(template_path, redirect_location, ret_code)
    M.redirect_location = redirect_location or ""

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
            ngx.log(ngx.ERR, "RET_CODE '" .. ret_code .. "' is not supported, using default HTTP code " .. M.ret_code)
        end
    end

    local template_file_ok = false
    if (template_path ~= nil and template_path ~= "" and utils.file_exist(template_path) == true) then
        local template_str = utils.read_file(template_path)
        if template_str ~= nil then
            -- Precompile template at init time for faster rendering
            M.compiled_template = template.precompile(template_str)
            if M.compiled_template ~= nil then
                template_file_ok = true
                ngx.log(ngx.DEBUG, "Ban template precompiled successfully")
            end
        end
    end

    if template_file_ok == false and (M.redirect_location == nil or M.redirect_location == "") then
        ngx.log(ngx.ERR, "BAN_TEMPLATE_PATH and REDIRECT_LOCATION variable are empty, will return HTTP " .. M.ret_code  .. " for ban decisions")
    end

    return nil
end

--- Apply the ban remediation
---@param ret_code? number Optional HTTP status code override
---@param extra_vars? table<string, string> Optional additional template variables
function M.apply(ret_code, extra_vars)
    ngx.log(ngx.DEBUG, "args:" .. tostring(ret_code))

    local status = ret_code or M.ret_code

    ngx.log(ngx.DEBUG, "BAN: status=" .. status .. ", redirect_location=" .. M.redirect_location)
    if M.redirect_location ~= "" then
        ngx.redirect(M.redirect_location)
        return
    end
    if M.compiled_template ~= nil then
        ngx.header.content_type = "text/html"
        ngx.header.cache_control = "no-cache"
        ngx.status = status

        -- Render precompiled template with request-specific variables
        local template_vars = template.get_request_vars(extra_vars)
        local rendered = template.render(M.compiled_template, template_vars)

        ngx.say(rendered)
        ngx.exit(status)
        return
    end

    ngx.exit(status)
end

return M
