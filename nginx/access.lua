local cs = require "crowdsec"


captcha_status = ngx.shared.crowdsec_cache:get("captcha_"..ngx.var.remote_addr)
if captcha_status == "to_verify" then
    ngx.req.read_body()
    local recaptcha_res = ngx.req.get_post_args()["g-recaptcha-response"] or 0
    if recaptcha_res ~= 0 then
        valid, err = cs.validateCaptcha(recaptcha_res, ngx.var.remote_addr)
        if valid == true then
            return
        else
            ngx.log(ngx.ALERT, "Invalid captcha from " .. ngx.var.remote_addr)
        end
    end
end

local ok, remediation, err = cs.allowIp(ngx.var.remote_addr)
if err ~= nil then 
    ngx.log(ngx.ERR, "[Crowdsec] bouncer error: " .. err)
end
if not ok then
    ngx.log(ngx.ALERT, "[Crowdsec] denied '" .. ngx.var.remote_addr .. "' with '"..remediation.."'")
    if remediation == "ban" then
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    if remediation == "captcha" then
        captcha_status = ngx.shared.crowdsec_cache:get("captcha_"..ngx.var.remote_addr)
        if captcha_status ~= "validated" then
            ngx.header.content_type = "text/html"
            ngx.say(cs.GetCaptchaTemplate())
            ngx.shared.crowdsec_cache:set("captcha_"..ngx.var.remote_addr, "to_verify")
        end
    end
end
