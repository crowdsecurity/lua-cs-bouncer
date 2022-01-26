local recaptcha = {}


local M = {_TYPE='module', _NAME='recaptcha.funcs', _VERSION='1.0-0'}

_VERIFY_STATE = "to_verify"
_VALIDATED_STATE = "validated"


M.State = {}
M.State["1"] = _VERIFY_STATE
M.State["2"] = _VALIDATED_STATE

M.SecretKey = ""
M.SiteKey = ""
M.Template = ""


function M.New(siteKey, secretKey, TemplateFilePath)
    M.SecretKey = secretKey
    M.SiteKey = siteKey

    captcha_template = read_file(runtime.conf["CAPTCHA_TEMPLATE_PATH"])
    local view = template.new(captcha_template)

    M.Template = tostring(view)
end


function table_to_encoded_url(args)
    local params = {}
    for k, v in pairs(args) do table.insert(params, k .. '=' .. v) end
    return table.concat(params, "&")
  end

function M.Validate(g_captcha_res, remote_ip)
    body = {
        secret   = runtime.recaptcha_secret_key,
        response = g_captcha_res,
        remoteip = remote_ip
      }

      local httpc = http.new()

      httpc:set_timeout(1)

      local res, err = httpc:request_uri(link, {
        method = "POST",
        body = body,
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded",
        },
      })

      res, err = post_http_request(recaptcha_verify_url, table_to_encoded_url(body))
      if err ~= nil then
        return true, err
      end

      result = cjson.decode(res.body)

      return result.success, nil
end


return recaptcha