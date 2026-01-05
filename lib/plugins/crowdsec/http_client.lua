-- HTTP Client Module
-- Provides unified HTTP client with support for:
-- - HTTP/HTTPS URLs (http://host:port/path)
-- - Unix sockets (unix:/path/to/socket)
-- - Connection pooling and keep-alive
-- - Both API key and TLS authentication
--
-- Usage:
--   local client = http_client.new("http://example.com:8081", {
--     timeouts = {connect=1000, send=1000, read=1000},
--     ssl_verify = true,
--     ssl_client_cert = "/path/to/cert",
--     ssl_client_priv_key = "/path/to/key"
--   })
--   local res, err = client:request_uri("/v1/decisions?ip=1.1.1.1", {headers={...}})

local http = require "resty.http"
local url = require "plugins.crowdsec.url"

local M = {}

-- Note: Connection pooling is handled by resty.http via set_keepalive()
-- Each Client object owns its own httpc instance

-- Client class
local Client = {}
Client.__index = Client

--- Parse URL and extract connection parameters
-- Supports:
--   unix:/path/to/socket
--   http://host:port/path
--   https://host:port/path
-- @param url_str string: The URL to parse
-- @return table: Parsed URL parameters with fields:
--   scheme: "unix", "http", or "https"
--   host: hostname or nil for unix
--   port: port number or nil for unix
--   path: path portion of URL
--   socket_path: socket path for unix scheme
--   is_unix: boolean indicating if this is a unix socket
--   connection_key: unique key for connection pooling
--   full_url: original URL string
function M.parse_url(url_str)
  if not url_str or url_str == "" then
    return nil, "URL cannot be empty"
  end

  local parsed = {
    full_url = url_str,
    is_unix = false,
    scheme = nil,
    host = nil,
    port = nil,
    path = nil,
    full_path = nil,
    query = nil,
    socket_path = nil,
    connection_key = nil
  }

  -- Check for unix socket format: unix:/path/to/socket or unix:/path/to/socket/http/path
  if url_str:match("^unix:") then
    parsed.scheme = "unix"
    parsed.is_unix = true
    -- Extract everything after "unix:"
    local after_scheme = url_str:match("^unix:(.+)$")
    if not after_scheme then
      return nil, "Invalid unix socket URL format: " .. url_str
    end
    
    -- For unix sockets, we need to separate socket path from HTTP path
    -- Common patterns:
    --   unix:/var/run/crowdsec.sock -> socket: /var/run/crowdsec.sock, path: /
    --   unix:/var/run/crowdsec.sock/v1/appsec -> socket: /var/run/crowdsec.sock, path: /v1/appsec
    --   unix:/tmp/sock -> socket: /tmp/sock, path: /
    
    -- Try to find where socket path ends and HTTP path begins
    -- Heuristic: Look for patterns like /v1/, /api/, or paths that start with common HTTP path prefixes
    -- If no clear separator, assume everything is the socket path
    
    -- Check if there's a path component that looks like an HTTP path
    -- Common HTTP path patterns: /v1/, /api/, /v2/, etc.
    local http_path_match = after_scheme:match("(/v%d+/.*)$") or 
                           after_scheme:match("(/api/.*)$") or
                           after_scheme:match("(/[^/]+/[^/]+/.*)$")  -- At least 2 path segments
    
    if http_path_match then
      -- Extract socket path (everything before the HTTP path)
      parsed.socket_path = after_scheme:sub(1, #after_scheme - #http_path_match)
      parsed.path = http_path_match
    else
      -- No clear HTTP path, treat everything as socket path
      parsed.socket_path = after_scheme
      parsed.path = "/"
    end
    
    -- Ensure socket_path starts with / if it doesn't already
    if parsed.socket_path and not parsed.socket_path:match("^/") then
      parsed.socket_path = "/" .. parsed.socket_path
    end
    
    parsed.full_path = parsed.path
    -- connection_key is "unix:/path" which is what resty.http expects in the host field
    parsed.connection_key = "unix:" .. parsed.socket_path
    return parsed
  end

  -- Parse HTTP/HTTPS URL
  local u = url.parse(url_str)
  
  if not u.scheme then
    return nil, "URL must have a scheme (http://, https://, or unix:)"
  end

  parsed.scheme = u.scheme:lower()
  
  if parsed.scheme ~= "http" and parsed.scheme ~= "https" then
    return nil, "Unsupported URL scheme: " .. parsed.scheme .. " (supported: http, https, unix)"
  end

  parsed.host = u.host
  parsed.port = u.port
  
  -- Set default ports if not specified
  if not parsed.port then
    if parsed.scheme == "https" then
      parsed.port = 443
    else
      parsed.port = 80
    end
  end

  parsed.path = u.path or "/"
  parsed.query = u.query
  parsed.full_path = parsed.path
  if parsed.query then
    local query_str = tostring(parsed.query)
    if query_str and query_str ~= "" then
      parsed.full_path = parsed.full_path .. "?" .. query_str
    end
  end
  
  -- Build connection key for pooling
  parsed.connection_key = parsed.scheme .. "://" .. parsed.host .. ":" .. parsed.port

  return parsed
end

--- Make simple HTTP request (like request_uri, for LAPI - backward compatibility)
-- This function creates a temporary client object internally
-- @param url_str string: Full URL (http://host:port/path or unix:/socket/path)
-- @param options table: Request options:
--   timeout: number (single timeout for all operations)
--   connect_timeout: number (optional, separate connect timeout)
--   send_timeout: number (optional, separate send timeout)
--   read_timeout: number (optional, separate read timeout)
--   method: string (default: "GET")
--   headers: table (HTTP headers)
--   body: string (request body)
--   ssl_verify: boolean (whether to verify SSL)
--   ssl_client_cert: string (optional, for TLS auth)
--   ssl_client_priv_key: string (optional, for TLS auth)
-- @return res: HTTP response object with .status and .body, or nil on error
-- @return err: Error message if failed
function M.request_uri(url_str, options)
  options = options or {}
  
  -- Parse URL once to split base and path/query
  local parsed, perr = M.parse_url(url_str)
  if not parsed then
    return nil, perr
  end
  
  local base_url
  local path_with_query = parsed.full_path or parsed.path or "/"

  if parsed.is_unix then
    base_url = "unix:" .. parsed.socket_path
  else
    base_url = parsed.scheme .. "://" .. parsed.host .. ":" .. parsed.port
  end
  
  -- Setup timeouts for client creation
  local timeouts = {}
  if options.timeout then
    timeouts.connect = options.timeout
    timeouts.send = options.timeout
    timeouts.read = options.timeout
  else
    timeouts.connect = options.connect_timeout or 1000
    timeouts.send = options.send_timeout or 1000
    timeouts.read = options.read_timeout or 1000
  end
  
  -- Create temporary client object (reuses connection pooling internally)
  local client, err = M.new(base_url, {
    timeouts = timeouts,
    ssl_verify = options.ssl_verify,
    ssl_client_cert = options.ssl_client_cert,
    ssl_client_priv_key = options.ssl_client_priv_key
  })
  
  if not client then
    return nil, err
  end
  
  -- Use client's request_uri method
  return client:request_uri(path_with_query ~= "" and path_with_query or "/", {
    method = options.method,
    headers = options.headers,
    body = options.body
  })
end

--- Create a new HTTP client object
-- Parse URL once and create a reusable client object
-- @param url_str string: URL (http://host:port, https://host:port, or unix:/path)
-- @param options table: Client options:
--   timeouts: table {connect, send, read} - timeout values in ms
--   ssl_verify: boolean - whether to verify SSL certificates
--   ssl_client_cert: string or cdata - (optional) path to client certificate for mTLS, or parsed PEM object
--   ssl_client_priv_key: string or cdata - (optional) path to client private key for mTLS, or parsed PEM object
--   keepalive_timeout: number - (optional) keep-alive timeout in ms
--   keepalive_pool_size: number - (optional) pool size
-- @return client: HTTP client object, or nil on error
-- @return err: Error message if failed
function M.new(url_str, options)
  options = options or {}
  
  -- Parse URL once
  local url_params, err = M.parse_url(url_str)
  if not url_params then
    return nil, err
  end
  
  -- Build connection key with mTLS info if applicable
  local connection_key = url_params.connection_key
  if options.ssl_client_cert and options.ssl_client_priv_key then
    connection_key = connection_key .. "|mtls"
  end
  
  -- Create client object with its own httpc instance
  local client = setmetatable({
    url_params = url_params,
    connection_key = connection_key,
    timeouts = options.timeouts or {connect=1000, send=1000, read=1000},
    ssl_verify = options.ssl_verify ~= false,  -- default true
    ssl_client_cert = options.ssl_client_cert,
    ssl_client_priv_key = options.ssl_client_priv_key,
    keepalive_timeout = options.keepalive_timeout,
    keepalive_pool_size = options.keepalive_pool_size,
    httpc = nil,  -- HTTP client instance (created on first use)
  }, Client)
  
  return client, nil
end

--- Get or create HTTP client instance (internal method)
-- Each client object owns its httpc instance
-- @return httpc: HTTP client object, or nil on error
-- @return err: Error message if failed
function Client:_get_httpc()
  -- After set_keepalive(), the httpc is in a closed state
  -- resty.http will reuse the underlying connection from its pool when we create a new httpc
  -- So we always create a new httpc instance here
  -- (The actual TCP connection is reused by resty.http internally)
  
  -- Create new HTTP client instance
  self.httpc = http.new()
  self.httpc:set_timeouts(self.timeouts.connect, self.timeouts.send, self.timeouts.read)
  
  -- Connect
  local connect_opts = {}
  
  if self.url_params.is_unix then
    -- For Unix sockets, resty.http expects the full "unix:/path" in the host field
    -- Use connection_key which already contains "unix:/path"
    connect_opts.host = self.url_params.connection_key
    -- Explicitly set scheme and port to nil for Unix sockets (resty.http requirement)
    connect_opts.scheme = nil
    connect_opts.port = nil
  else
    connect_opts.scheme = self.url_params.scheme
    connect_opts.host = self.url_params.host
    connect_opts.port = self.url_params.port
  end
  
  connect_opts.ssl_verify = self.ssl_verify
  
  if self.ssl_client_cert and self.ssl_client_priv_key then
    connect_opts.ssl_client_cert = self.ssl_client_cert
    connect_opts.ssl_client_priv_key = self.ssl_client_priv_key
  end
  
  local ok, err = self.httpc:connect(connect_opts)
  if not ok then
    self.httpc = nil
    return nil, "Failed to connect: " .. (err or "unknown")
  end
  
  return self.httpc, nil
end

--- Release HTTP client back to keep-alive pool (internal method)
-- Uses resty.http's built-in connection pooling via set_keepalive
-- @return ok: boolean indicating success
-- @return err: Error message if failed
function Client:_release_httpc()
  if not self.httpc then
    return true, nil
  end
  
  -- Check if keepalive_timeout and keepalive_pool_size are set
  -- If not, just close the connection (no keep-alive)
  if not self.keepalive_timeout or not self.keepalive_pool_size then
    pcall(function() self.httpc:close() end)
    self.httpc = nil
    return true, nil
  end
  
  -- Try to set keepalive - use pcall to safely handle any errors
  local success, ok, err = pcall(function()
    return self.httpc:set_keepalive(self.keepalive_timeout, self.keepalive_pool_size)
  end)
  
  if not success then
    -- pcall failed - set_keepalive threw an error (ok contains the error message)
    pcall(function() self.httpc:close() end)
    self.httpc = nil
    return false, "Failed to set keepalive: " .. tostring(ok)
  end
  
  -- Check if set_keepalive returned success (ok is boolean, err is error message if failed)
  if not ok then
    -- set_keepalive returned false
    pcall(function() self.httpc:close() end)
    self.httpc = nil
    return false, "Failed to set keepalive: " .. (tostring(err) or "unknown")
  end
  
  -- After set_keepalive(), the httpc object is in a "closed" state but the connection
  -- is in resty.http's pool. Clear the reference - we'll create a new httpc on next request,
  -- and resty.http will automatically reuse the underlying connection from its pool.
  self.httpc = nil
  return true, nil
end

--- Build request path by joining base path from URL and provided path
-- @param path string: Request path (may be absolute or relative, may include query string)
-- @return string: Normalized path including base path and merged query strings
function Client:_build_path(path)
  local function normalize(p)
    if not p or p == "" then
      return "/"
    end
    -- Remove query string and fragment for path normalization
    p = p:gsub("%?.*$", ""):gsub("#.*$", "")
    if p:sub(1,1) ~= "/" then
      return "/" .. p
    end
    return p
  end

  local base_path = normalize(self.url_params.path or "/")
  
  -- Extract query strings
  local path_query = ""
  local url_query = ""
  if self.url_params.query then
    url_query = tostring(self.url_params.query)
  end
  
  if path then
    local query_match = path:match("%?([^#]+)")
    if query_match then
      path_query = query_match
    end
  end

  -- If caller passes no path (or just "/"), use configured base path + query
  if not path or path == "" or path == "/" then
    if url_query ~= "" then
      return base_path .. "?" .. url_query
    end
    return base_path
  end

  local normalized_extra = normalize(path)

  -- If caller already provided a path with the base prefix, keep it as-is
  if base_path ~= "/" and normalized_extra:sub(1, #base_path) == base_path then
    -- Merge query strings
    if path_query ~= "" and url_query ~= "" then
      return normalized_extra .. "?" .. path_query .. "&" .. url_query
    elseif path_query ~= "" then
      return normalized_extra .. "?" .. path_query
    elseif url_query ~= "" then
      return normalized_extra .. "?" .. url_query
    end
    return normalized_extra
  end

  -- Build final path
  local final_path
  if base_path == "/" then
    final_path = normalized_extra
  elseif base_path:sub(-1) == "/" then
    final_path = base_path .. normalized_extra:sub(2)
  else
    final_path = base_path .. normalized_extra
  end
  
  -- Merge query strings
  if path_query ~= "" and url_query ~= "" then
    return final_path .. "?" .. path_query .. "&" .. url_query
  elseif path_query ~= "" then
    return final_path .. "?" .. path_query
  elseif url_query ~= "" then
    return final_path .. "?" .. url_query
  end
  
  return final_path
end

--- Make HTTP request with full control
-- @param client: Client object (self)
-- @param method string: HTTP method (GET, POST, etc.)
-- @param path string: Request path
-- @param headers table: HTTP headers
-- @param body string: (optional) Request body
-- @return res: HTTP response object, or nil on error
-- @return err: Error message if failed
function Client:request(method, path, headers, body)
  local httpc, err = self:_get_httpc()
  if not httpc then
    return nil, err
  end
  
  -- Set Host header appropriately
  if not headers then
    headers = {}
  end
  
  if self.url_params.is_unix then
    if not headers["Host"] and not headers["host"] then
      headers["Host"] = "localhost"
    end
  else
    if not headers["Host"] and not headers["host"] then
      local host_header = self.url_params.host
      if self.url_params.port and 
         ((self.url_params.scheme == "http" and self.url_params.port ~= 80) or
          (self.url_params.scheme == "https" and self.url_params.port ~= 443)) then
        host_header = host_header .. ":" .. self.url_params.port
      end
      headers["Host"] = host_header
    end
  end
  
  local full_path = self:_build_path(path)

  -- Make request
  local res, err = httpc:request({
    method = method,
    path = full_path,
    headers = headers,
    body = body
  })
  
  if not res then
    -- Request failed, clear httpc so we create a new one next time
    self.httpc:close()
    self.httpc = nil
    return nil, err or "Request failed"
  end
  
  -- Read response body
  local body_str, err = res:read_body()
  if err then
    ngx.log(ngx.WARN, "Failed to read response body: " .. err)
  else
    res.body = body_str
  end
  
  -- Return connection to keep-alive pool (resty.http handles pooling)
  self:_release_httpc()
  
  return res, nil
end

--- Make HTTP request using only the base path from URL (no additional path needed)
-- Useful for services like AppSec that always use the configured base path
-- @param client: Client object (self)
-- @param options table: Request options:
--   method: string (default: "GET")
--   headers: table (HTTP headers)
--   body: string (request body)
-- @return res: HTTP response object with .status and .body, or nil on error
-- @return err: Error message if failed
function Client:request_base(options)
  return self:request_uri("", options)
end

--- Make simple HTTP request (like request_uri)
-- @param client: Client object (self)
-- @param path string: Request path (can include query string)
-- @param options table: Request options:
--   method: string (default: "GET")
--   headers: table (HTTP headers)
--   body: string (request body)
-- @return res: HTTP response object with .status and .body, or nil on error
-- @return err: Error message if failed
function Client:request_uri(path, options)
  options = options or {}
  
  -- Build full path (include base path and query if configured)
  local full_path = self:_build_path(path)
  
  -- Get or create client
  local httpc, err = self:_get_httpc()
  if not httpc then
    return nil, err
  end
  
  -- Prepare headers
  local headers = options.headers or {}
  
  -- Set Host header appropriately
  if self.url_params.is_unix then
    if not headers["Host"] and not headers["host"] then
      headers["Host"] = "localhost"
    end
  else
    if not headers["Host"] and not headers["host"] then
      local host_header = self.url_params.host
      if self.url_params.port and 
         ((self.url_params.scheme == "http" and self.url_params.port ~= 80) or
          (self.url_params.scheme == "https" and self.url_params.port ~= 443)) then
        host_header = host_header .. ":" .. self.url_params.port
      end
      headers["Host"] = host_header
    end
  end
  
  -- Remove Connection: close header if present (we want keep-alive)
  headers["Connection"] = nil
  headers["connection"] = nil
  
  -- Make request
  local res, err = httpc:request({
    method = options.method or "GET",
    path = full_path,
    headers = headers,
    body = options.body
  })
  
  if not res then
    -- Request failed, clear httpc so we create a new one next time
    self.httpc:close()
    self.httpc = nil
    return nil, err or "Request failed"
  end
  
  -- Read response body
  local body_str, err = res:read_body()
  if err then
    ngx.log(ngx.WARN, "Failed to read response body: " .. err)
    res.body = ""
  else
    res.body = body_str
  end
  
  -- Return connection to keep-alive pool (resty.http handles pooling)
  self:_release_httpc()
  
  return res, nil
end

return M
