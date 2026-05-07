local M = {_TYPE='module', _NAME='challenge.funcs', _VERSION='1.0-0'}

--- Serve a challenge response from AppSec.
-- Sets the HTTP status, response headers, cookies, and body as provided by CrowdSec.
-- @param status_code number: HTTP status code (typically 200)
-- @param body string: the HTML body content to serve
-- @param headers table: map of header name -> list of values, e.g. {["Content-Type"] = {"text/html"}}
-- @param cookies table: list of Set-Cookie header value strings
function M.apply(status_code, body, headers, cookies)
    ngx.status = status_code or ngx.HTTP_OK

    if headers ~= nil then
        for name, values in pairs(headers) do
            if type(values) == "table" then
                if #values == 1 then
                    ngx.header[name] = values[1]
                else
                    ngx.header[name] = values
                end
            else
                ngx.header[name] = values
            end
        end
    end

    if cookies ~= nil and #cookies > 0 then
        if #cookies == 1 then
            ngx.header["Set-Cookie"] = cookies[1]
        else
            ngx.header["Set-Cookie"] = cookies
        end
    end

    if body ~= nil then
        ngx.say(body)
    end

    ngx.exit(ngx.status)
end

return M
