local utils = require "plugins.crowdsec.utils"


local M = {_TYPE='module', _NAME='ban.funcs', _VERSION='1.0-0'}

M.template_str = ""
M.redirect_location = ""
M.ret_code = ngx.HTTP_FORBIDDEN


function M.new(template_path, redirect_location, ret_code)
    if template_path == nil then
        return "ban template file variable is empty, will ban without template"
    end
    if utils.file_exist(template_path) == false then
        return "ban template file doesn't exist, will ban without template"
    else
        M.template_str = utils.read_file(template_path)
        if M.template_str == nil then
            M.template_str = ""
            return "ban template file doesn't exist, will ban without template"
        end
    end

    M.redirect_location = redirect_location

    for k, v in pairs(utils.HTTP_CODE) do
        if k == ret_code then
            M.ret_code = utils.HTTP_CODE[ret_code]
            break
        end
    end

    return nil
end


function M.apply()
    if M.redirect_location ~= "" then
        ngx.redirect(M.redirect_location)
        return
    end
    if M.template_str ~= "" then
        ngx.header.content_type = "text/html"
        ngx.status = M.ret_code
        ngx.say(M.template_str)
        return
    end
 
    ngx.exit(M.ret_code)

    return
end

return M