local config = {}

function config.file_exists(file)
    local f = io.open(file, "rb")
    if f then 
        f:close() 
    end
    return f ~= nil
end

  function split(s, delimiter)
    result = {};
    for match in (s..delimiter):gmatch("(.-)"..delimiter.."(.-)") do
        table.insert(result, match);
    end
    return result;
end

local function has_value (tab, val)
    for index, value in ipairs(tab) do
        if value == val then
            return true
        end
    end

    return false
end

local function starts_with(str, start)
    return str:sub(1, #start) == start
end

function config.loadConfig(file)
    if not config.file_exists(file) then
        return nil, "File".. file .." doesn't exist"
    end
    local conf = {}
    local valid_params = {'API_URL', 'API_KEY', 'LOG_FILE'}
    local valid_int_params = {'CACHE_EXPIRATION', 'CACHE_SIZE'}
    for line in io.lines(file) do
        local isOk = false
        if starts_with(line, "#") then
            isOk = true
        end
        if not isOk then
            local s = split(line, "=")
            for k, v in pairs(s) do
                if has_value(valid_params, v) then
                    local n = next(s, k)
                    conf[v] = s[n]
                    break
                elseif has_value(valid_int_params, v) then
                    local n = next(s, k)
                    conf[v] = tonumber(s[n])
                    break
                else
                    print("unsupported configuration '" .. v .. "'")
                end
            end
        end
    end
    return conf, nil
end

return config