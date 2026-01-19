local utils = require "plugins.crowdsec.utils"
local template = require "plugins.crowdsec.template"


local M = {_TYPE='module', _NAME='ban.funcs', _VERSION='1.0-0'}

M.template_str = ""
M.redirect_location = ""
M.ret_code = ngx.HTTP_FORBIDDEN


function M.new(template_path, redirect_location, ret_code)
    M.redirect_location = redirect_location

    ret_code_ok = false
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

    template_file_ok = false
    if (template_path ~= nil and template_path ~= "" and utils.file_exist(template_path) == true) then
        M.template_str = utils.read_file(template_path)
        if M.template_str ~= nil then
            template_file_ok = true
        end
    end

    if template_file_ok == false and (M.redirect_location == nil or M.redirect_location == "") then
        ngx.log(ngx.ERR, "BAN_TEMPLATE_PATH and REDIRECT_LOCATION variable are empty, will return HTTP " .. M.ret_code  .. " for ban decisions")
    end

    return nil
end


-- Generate a unique request ID
local function generate_request_id()
    -- Use ngx.var.request_id if available (OpenResty 1.11.2+)
    if ngx.var.request_id then
        return ngx.var.request_id
    end
    -- Fallback: generate a simple unique ID
    local random_part = string.format("%08x", math.random(0, 0xFFFFFFFF))
    local time_part = string.format("%08x", ngx.now() * 1000)
    return time_part .. "-" .. random_part
end


-- Gather template variables from the current request context
local function get_template_vars(extra_vars)
    local vars = {
        -- Request identification
        request_id = generate_request_id(),

        -- Client information
        client_ip = ngx.var.remote_addr or "",
        client_port = ngx.var.remote_port or "",

        -- Request details
        request_uri = ngx.var.request_uri or "",
        request_method = ngx.var.request_method or "",
        host = ngx.var.host or "",
        server_name = ngx.var.server_name or "",
        scheme = ngx.var.scheme or "",

        -- User agent and headers
        user_agent = ngx.var.http_user_agent or "",
        referer = ngx.var.http_referer or "",

        -- Timing
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
        timestamp_iso = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        timestamp_unix = tostring(os.time()),

        -- Server info
        server_addr = ngx.var.server_addr or "",
        server_port = ngx.var.server_port or "",
    }

    -- Merge in any extra variables passed (e.g., from CrowdSec decision)
    if extra_vars then
        for k, v in pairs(extra_vars) do
            vars[k] = v
        end
    end

    return vars
end


function M.apply(...)
    local args = {...}
    local ret_code = args[1]
    local extra_vars = args[2]  -- Optional table of additional template variables

    ngx.log(ngx.DEBUG, "args:" .. tostring(args[1]))

    local status = 0
    if ret_code ~= nil then
        status = ret_code
    else
        status = M.ret_code
    end

    ngx.log(ngx.DEBUG, "BAN: status=" .. status .. ", redirect_location=" .. M.redirect_location .. ", template_str=" .. M.template_str)
    if M.redirect_location ~= "" then
        ngx.redirect(M.redirect_location)
        return
    end
    if M.template_str ~= "" then
        ngx.header.content_type = "text/html"
        ngx.header.cache_control = "no-cache"
        ngx.status = status

        -- Compile template with request-specific variables
        local template_vars = get_template_vars(extra_vars)
        local compiled = template.compile(M.template_str, template_vars)

        ngx.say(compiled)
        ngx.exit(status)
        return
    end

    ngx.exit(status)

    return
end

return M
