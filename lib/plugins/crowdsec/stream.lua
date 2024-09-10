local utils = require "plugins.crowdsec.utils"
local cjson = require "cjson"
local runtime = {}

runtime.cache = ngx.shared.crowdsec_cache

local function set_refreshing(value)
  local succ, err, forcible = runtime.cache:set("refreshing", value)
  if not succ then
    error("Failed to set refreshing key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end
end

local function parse_duration(duration)
  local match, err = ngx.re.match(duration, "^((?<hours>[0-9]+)h)?((?<minutes>[0-9]+)m)?(?<seconds>[0-9]+)")
  local ttl = 0
  if not match then
    if err then
      return ttl, err
    end
  end
  if match["hours"] ~= nil and match["hours"] ~= false then
    local hours = tonumber(match["hours"])
    ttl = ttl + (hours * 3600)
  end
  if match["minutes"] ~= nil and match["minutes"] ~= false then
    local minutes = tonumber(match["minutes"])
    ttl = ttl + (minutes * 60)
  end
  if match["seconds"] ~= nil and match["seconds"] ~= false then
    local seconds = tonumber(match["seconds"])
    ttl = ttl + seconds
  end
  return ttl, nil
end



function StreamQuery(premature, api_url, update_frequency, bouncing_on_type)
  -- As this function is running inside coroutine (with ngx.timer.at),
  -- we need to raise error instead of returning them

  if api_url == "" then
    return
  end

  ngx.log(ngx.DEBUG, "running timers: " .. tostring(ngx.timer.running_count()) .. " | pending timers: " .. tostring(ngx.timer.pending_count()))

  if premature then
    ngx.log(ngx.DEBUG, "premature run of the timer, returning")
    return
  end

  local refreshing = runtime.cache:get("refreshing")

  if refreshing == true then
    ngx.log(ngx.DEBUG, "another worker is refreshing the data, returning")
    local ok, err = ngx.timer.at(update_frequency, StreamQuery)
    if not ok then
      error("Failed to create the timer: " .. (err or "unknown"))
    end
    return
  end

  local last_refresh = runtime.cache:get("last_refresh")
  if last_refresh ~= nil then
      -- local last_refresh_time = tonumber(last_refresh)
      local now = ngx.time()
      if now - last_refresh < update_frequency then
        ngx.log(ngx.DEBUG, "last refresh was less than " .. update_frequency .. " seconds ago, returning")
        local ok, err = ngx.timer.at(update_frequency, StreamQuery)
        if not ok then
          error("Failed to create the timer: " .. (err or "unknown"))
        end
        return
      end
  end

  set_refreshing(true)

  local is_startup = runtime.cache:get("startup")
  ngx.log(ngx.DEBUG, "Stream Query from worker : " .. tostring(ngx.worker.id()) .. " with startup "..tostring(is_startup) .. " | premature: " .. tostring(premature))
  local link = runtime.conf["API_URL"] .. "/v1/decisions/stream?startup=" .. tostring(is_startup)
  local res, err = utils.get_remediation_http_request(link)
  if not res then
    local ok, err2 = ngx.timer.at(update_frequency, StreamQuery)
    if not ok then
      set_refreshing(false)
      error("Failed to create the timer: " .. (err2 or "unknown"))
    end
    set_refreshing(false)
    error("request failed: ".. err)
  end

  local succ, err, forcible = runtime.cache:set("last_refresh", ngx.time())
  if not succ then
    error("Failed to set last_refresh key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end

  local status = res.status
  local body = res.body

  ngx.log(ngx.DEBUG, "Response:" .. tostring(status) .. " | " .. tostring(body))

  if status~=200 then
    local ok, err = ngx.timer.at(update_frequency, StreamQuery)
    if not ok then
      set_refreshing(false)
      error("Failed to create the timer: " .. (err or "unknown"))
    end
    set_refreshing(false)
    error("HTTP error while request to Local API '" .. status .. "' with message (" .. tostring(body) .. ")")
  end

  local decisions = cjson.decode(body)
  -- process deleted decisions
  if type(decisions.deleted) == "table" then
      for i, decision in pairs(decisions.deleted) do
        if decision.type == "captcha" then
          runtime.cache:delete("captcha_" .. decision.value)
        end
        local key = utils.item_to_string(decision.value, decision.scope)
        runtime.cache:delete(key)
        ngx.log(ngx.DEBUG, "Deleting '" .. key .. "'")
      end
  end

  -- process new decisions
  if type(decisions.new) == "table" then
    for i, decision in pairs(decisions.new) do
      if bouncing_on_type == decision.type or bouncing_on_type == "all" then
        local ttl, err = parse_duration(decision.duration)
        if err ~= nil then
          ngx.log(ngx.ERR, "[Crowdsec] failed to parse ban duration '" .. decision.duration .. "' : " .. err)
        end
        local key = utils.item_to_string(decision.value, decision.scope)
        local succ, err, forcible = runtime.cache:set(key, decision.type .. "/" .. decision.origin, ttl, 0)
        ngx.log(ngx.INFO, "Adding '" .. key .. "' in cache for '" .. tostring(ttl) .. "' seconds " .. tostring(remediation_id+origin_id*4)) -- debug
        if not succ then
          ngx.log(ngx.ERR, "failed to add ".. decision.value .." : "..err)
        end
        if forcible then
          ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
        end

      end
    end
  end

  -- not startup anymore after first callback
  local succ, err, forcible = runtime.cache:set("startup", false)
  if not succ then
    ngx.log(ngx.ERR, "failed to set startup key in cache: "..err)
  end
  if forcible then
    ngx.log(ngx.ERR, "Lua shared dict (crowdsec cache) is full, please increase dict size in config")
  end


  local ok, err = ngx.timer.at(update_frequency, StreamQuery)
  if not ok then
    set_refreshing(false)
    error("Failed to create the timer: " .. (err or "unknown"))
  end

  set_refreshing(false)
  ngx.log(ngx.DEBUG, "end of stream_query")
  return nil
end