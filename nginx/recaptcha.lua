--local template = require "resty.template.safe"
local http = require "resty.http"
local cjson = require "cjson"
local template = require "plugins.crowdsec.template"


local M = {_TYPE='module', _NAME='recaptcha.funcs', _VERSION='1.0-0'}

local recaptcha_verify_url = "https://www.google.com/recaptcha/api/siteverify"

M._VERIFY_STATE = "to_verify"
M._VALIDATED_STATE = "validated"


M.State = {}
M.State["1"] = M._VERIFY_STATE
M.State["2"] = M._VALIDATED_STATE

M.SecretKey = ""
M.SiteKey = ""
M.Template = ""


function M.GetStateID(state)
    for k, v in pairs(M.State) do
        if v == state then
            return tonumber(k)
        end
    end
    return nil
end

local function read_file(path)
    local file = io.open(path, "r") -- r read mode and b binary mode
    if not file then return nil end
    io.input(file)
    content = io.read("*a")
    io.close(file)
    return content
  end

local function file_exist(path)
  local f = io.open(path, "r")
  if f ~= nil then 
    io.close(f)
    return true 
  else 
    return false
  end
end

function M.New(siteKey, secretKey, TemplateFilePath)

    if siteKey == nil or siteKey == "" then
      return "no recaptcha site key provided, can't use recaptcha"
    end
    M.SiteKey = siteKey

    if secretKey == nil or secretKey == "" then
      return "no recaptcha secret key provided, can't use recaptcha"
    end

    M.SecretKey = secretKey

    if file_exist(TemplateFilePath) == false then
      return "captcha template file doesn't exist, can't use recaptcha"
    end

    local captcha_template = read_file(TemplateFilePath)
    if captcha_template == nil then
        return "Template file " .. TemplateFilePath .. "not found."
    end

    template_data = {}
    template_data["recaptcha_site_key"] =  m.SiteKey
    local view = template.compile(captcha_template, template_data)
    M.Template = view

    return nil
end


function M.GetTemplate()
    return M.Template
end


function table_to_encoded_url(args)
    local params = {}
    for k, v in pairs(args) do table.insert(params, k .. '=' .. v) end
    return table.concat(params, "&")
  end

function M.Validate(g_captcha_res, remote_ip)
    body = {
        secret   = M.SecretKey,
        response = g_captcha_res,
        remoteip = remote_ip
      }

      data = table_to_encoded_url(body)
      local httpc = http.new()
      httpc:set_timeout(1000)
      local res, err = httpc:request_uri(recaptcha_verify_url, {
        method = "POST",
        body = data,
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded",
        },
      })
      if err ~= nil then
        return true, err
      end

      result = cjson.decode(res.body)

      return result.success, nil
end


return M