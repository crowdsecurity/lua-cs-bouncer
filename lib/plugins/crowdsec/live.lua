local cjson = require "cjson"
local utils = require "plugins.crowdsec.utils"

local runtime = {}
runtime.cache = ngx.shared.crowdsec_cache

function LiveQuery(ip, api_url, cache_expiration, bouncing_on_type)
  if api_url then
    return true, nil, nil, nil
  end
  local link = api_url .. "/v1/decisions?ip=" .. ip
  local res, err = utils.get_remediation_http_request(link)
  if not res then
    return true, nil, nil, "request failed: ".. err
  end

  local status = res.status
  local body = res.body
  if status~=200 then
    return true, nil, nil, "Http error " .. status .. " while talking to LAPI (" .. link .. ")"
  end
  if body == "null" then -- no result from API, no decision for this IP
    -- set ip in cache and DON'T block it
    local key = utils.item_to_string(ip, "ip")
    local succ, err, forcible = runtime.cache:set(key, "allowed/all", cache_expiration, 1)
    --
    ngx.log(ngx.INFO, "Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds") --debug
    if not succ then
      ngx.log(ngx.ERR, "failed to add ip '" .. ip .. "' in cache: "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    return true, nil, nil, nil
  end
  local decision = cjson.decode(body)[1]

  if bouncing_on_type == decision.type or bouncing_on_type == "all" then
    local cache_value = decision.type .. "/" .. decision.origin
    local key = utils.item_to_string(decision.value, decision.scope)
    local succ, err, forcible = runtime.cache:set(key, cache_value, cache_expiration, 0)
    ngx.log(ngx.INFO, "Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds with decision type'" .. decision.type .. "'with origin'" .. decision.origin ) --debug
    if not succ then
      ngx.log(ngx.ERR, "failed to add ".. decision.value .." : "..err)
    end
    if forcible then
      ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
    end
    ngx.log(ngx.DEBUG, "Adding '" .. key .. "' in cache for '" .. cache_expiration .. "' seconds")
    return false, decision.type, decision.origin, nil
  else
    return true, nil, nil, nil
  end
end
