local iputils = require "plugins.crowdsec.iputils"
local http = require "resty.http"

local M = {}


M.HTTP_CODE = {}
M.HTTP_CODE["200"] = ngx.HTTP_OK
M.HTTP_CODE["202"] = ngx.HTTP_ACCEPTED
M.HTTP_CODE["204"] = ngx.HTTP_NO_CONTENT
M.HTTP_CODE["301"] = ngx.HTTP_MOVED_PERMANENTLY
M.HTTP_CODE["302"] = ngx.HTTP_MOVED_TEMPORARILY
M.HTTP_CODE["400"] = ngx.HTTP_BAD_REQUEST
M.HTTP_CODE["401"] = ngx.HTTP_UNAUTHORIZED
M.HTTP_CODE["401"] = ngx.HTTP_UNAUTHORIZED
M.HTTP_CODE["403"] = ngx.HTTP_FORBIDDEN
M.HTTP_CODE["404"] = ngx.HTTP_NOT_FOUND
M.HTTP_CODE["405"] = ngx.HTTP_NOT_ALLOWED
M.HTTP_CODE["406"] = ngx.HTTP_NOT_ACCEPTABLE
M.HTTP_CODE["444"] = ngx.HTTP_CLOSE
M.HTTP_CODE["500"] = ngx.HTTP_INTERNAL_SERVER_ERROR

function M.read_file(path)
   local file = io.open(path, "r") -- r read mode and b binary mode
   if not file then return nil end
   io.input(file)
   local content = io.read("*a")
   io.close(file)
   return content:sub(1,-2)
 end

function M.file_exist(path)
 if path == nil then
   return nil
 end
 local f = io.open(path, "r")
 if f ~= nil then 
   io.close(f)
   return true 
 else 
   return false
 end
end

function M.starts_with(str, start)
    return str:sub(1, #start) == start
 end
 
 function M.ends_with(str, ending)
    return ending == "" or str:sub(-#ending) == ending
 end

function M.table_len(table)
   local count = 0
   for k, v in pairs(table) do
      count = count + 1
   end
   return count
end

function M.item_to_string(item, scope)
  local ip, cidr, ip_version
  if scope:lower() == "ip" then
    ip = item
  end
  if scope:lower() == "range" then
    ip, cidr = iputils.splitRange(item, scope)
  end

  local ip_network_address, is_ipv4 = iputils.parseIPAddress(ip)
  if ip_network_address == nil then
    return nil, nil
  end
  if is_ipv4 then
    ip_version = "ipv4"
    if cidr == nil then
      cidr = 32
    end
  else
    ip_version = "ipv6"
    ip_network_address = ip_network_address.uint32[3]..":"..ip_network_address.uint32[2]..":"..ip_network_address.uint32[1]..":"..ip_network_address.uint32[0]
    if cidr == nil then
      cidr = 128
    end
  end

  if ip_version == nil then
    return "normal_"..item, ip_version
  end
  local ip_netmask = iputils.cidrToInt(cidr, ip_version)
  return ip_version.."_"..ip_netmask.."_"..ip_network_address, ip_version
end

function M.get_remediation_http_request(link,timeout, api_key_header, api_key, user_agent,ssl_verify)
  local httpc = http.new()
  httpc:set_timeout(timeout)
  local res, err = httpc:request_uri(link, {
    method = "GET",
    headers = {
      ['Connection'] = 'close',
      [api_key_header] = api_key,
      ['User-Agent'] = user_agent
    },
    ssl_verify = ssl_verify
  })
  httpc:close()
  return res, err
end

function M.split_on_delimiter(str, delimiter)
  if str == nil then
    return nil
  end

  ngx.log(ngx.DEBUG, "split_on_delimiter: " .. str .. " using delimiter: " .. delimiter)

  local result = {}
  local pattern = "([^" .. delimiter .. "]+)"  -- Create a pattern to match between delimiters

  for word in string.gmatch(str, pattern) do
    table.insert(result, word)  -- Insert the split parts into the result table
  end

  return result  -- Return the split parts as a table
end

--- Convert a labels key, value table to a string.
--- @param t table to convert.
--- @return table ordered table
function M.table_to_string(t)
    local sorted_keys = {}

    -- Collect all keys and sort them
    for key in pairs(t) do
      table.insert(sorted_keys, key)
    end
    table.sort(sorted_keys)

    -- Build an ordered version of the table
    local ret = ""
    for  _, key in pairs(sorted_keys) do
      ret = ret .. key .. "=" .. t[key] .. "&"
    end

    -- Convert ordered table to JSON string
    return ret
end

--- Convert a string to a labels key, value table.
--- @param str string to convert.
--- @return table ordered table
function M.string_to_table(str)
  local t = {}
  if str == nil then
    return {}
  end
  local labels_string = M.split_on_delimiter(str, "&")
  if labels_string == nil then
    return {}
  end
  for _, v in pairs(labels_string) do
    ngx.log(ngx.DEBUG, "dealing with:" .. v)
    local label = M.split_on_delimiter(v, "=")
    if label ~= nil and  #label == 2 then
      t[label[1]] = label[2]
    end
  end
  return t
end

return M

