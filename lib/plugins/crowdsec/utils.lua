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
      ngx.log(ngx.DEBUG, "label key=value:" .. key .. "=" .. t[key])
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

--- Create and configure an HTTP client based on parsed URL configuration
--- @param api_url string: the API URL to parse and configure for
--- @param timeout_config table: timeout configuration {connect, send, read}
--- @param ssl_verify boolean: whether to verify SSL certificates
--- @param user_agent string: user agent for requests
--- @param api_key_header string: API key header name
--- @param api_key string: API key value
--- @return httpc: configured HTTP client
--- @return table: connection configuration for reuse
--- @return string: error message if any
function M.create_http_client(api_url, timeout_config, ssl_verify, user_agent, api_key_header, api_key)
  local url = require "plugins.crowdsec.url"
  local http = require "resty.http"
  
  if api_url == "" then
    return nil, nil, "API URL is empty"
  end
  
  -- Parse the URL
  local parsed_url = url.parse(api_url)
  if not parsed_url then
    return nil, nil, "Failed to parse API URL: " .. api_url
  end
  
  -- Create HTTP client
  local httpc = http.new()
  
  -- Set timeouts
  local connect_timeout = timeout_config.connect or 1000
  local send_timeout = timeout_config.send or 5000  
  local read_timeout = timeout_config.read or 5000
  
  httpc:set_timeouts(connect_timeout, send_timeout, read_timeout)
  
  -- Prepare connection configuration
  local connection_config = {
    ssl_verify = ssl_verify,
    parsed_url = parsed_url,
    headers = {
      ['User-Agent'] = user_agent,
      [api_key_header] = api_key
    }
  }
  
  -- Handle different connection types
  if parsed_url.scheme == "unix" then
    -- Unix socket configuration
    connection_config.connection_opts = {
      scheme = "unix",
      host = parsed_url.url, -- For unix sockets, the full URL is the socket path
      ssl_verify = ssl_verify
    }
    connection_config.base_path = "/"
    connection_config.headers['Host'] = "localhost"
  else
    -- TCP configuration
    connection_config.connection_opts = {
      scheme = parsed_url.scheme or "http",
      host = parsed_url.host,
      port = parsed_url.port,
      ssl_verify = ssl_verify
    }
    connection_config.base_path = parsed_url.path or "/"
    connection_config.headers['Host'] = parsed_url.host
    if parsed_url.port and parsed_url.port ~= 80 and parsed_url.port ~= 443 then
      connection_config.headers['Host'] = connection_config.headers['Host'] .. ":" .. parsed_url.port
    end
  end
  
  return httpc, connection_config, nil
end

--- Make HTTP request using pre-configured client and connection config
--- @param httpc: HTTP client instance
--- @param connection_config table: connection configuration
--- @param path string: request path (will be appended to base_path)
--- @param method string: HTTP method (default: GET)
--- @param additional_headers table: additional headers to merge
--- @param body string: request body
--- @return res: HTTP response with body
--- @return string: error message if any
function M.make_http_request(httpc, connection_config, path, method, additional_headers, body)
  method = method or "GET"
  
  -- Connect if not already connected
  local ok, err = httpc:connect(connection_config.connection_opts)
  if not ok then
    return nil, "Failed to connect: " .. (err or "unknown error")
  end
  
  -- Prepare headers
  local headers = {}
  for k, v in pairs(connection_config.headers) do
    headers[k] = v
  end
  if additional_headers then
    for k, v in pairs(additional_headers) do
      headers[k] = v
    end
  end
  
  -- Add connection keep-alive for reuse
  headers['Connection'] = 'keep-alive'
  
  -- Prepare full path
  local full_path = connection_config.base_path
  if full_path ~= "/" and not M.ends_with(full_path, "/") then
    full_path = full_path .. "/"
  end
  if path and path ~= "" then
    if M.starts_with(path, "/") then
      path = path:sub(2) -- Remove leading slash
    end
    full_path = full_path .. path
  end
  
  -- Make request
  local res, err = httpc:request({
    path = full_path,
    method = method,
    headers = headers,
    body = body
  })
  
  if err then
    return nil, "Request failed: " .. err
  end
  
  if not res then
    return nil, "No response received"
  end
  
  -- Read body
  local response_body, body_err = res:read_body()
  if body_err then
    return nil, "Failed to read response body: " .. body_err
  end
  
  res.body = response_body
  
  -- Keep connection alive for reuse
  httpc:set_keepalive(30000, 100)
  
  return res, nil
end

return M

