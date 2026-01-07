-- HTTP Client Module
-- Provides unified HTTP client that automatically handles:
-- - HTTP/HTTPS URLs (http://host:port/path or https://host:port/path)
-- - Unix domain sockets (unix:/path/to/socket or unix:/path/to/socket/http/path)
-- - Connection pooling and keep-alive (via resty.http)
-- - API key authentication (via headers)
-- - Mutual TLS (mTLS) authentication (via client certificates)
--
-- The client abstracts away all connection details - callers just provide a URL
-- and configuration, then make requests without worrying about the underlying
-- transport mechanism.
--
-- Usage:
--   -- Create client once with URL and configuration
--   local client = http_client.new("http://example.com:8081", {
--     timeouts = {connect=1000, send=1000, read=1000},
--     ssl_verify = true,
--     api_key = "your-api-key",
--     user_agent = "my-app/1.0"
--   })
--   
--   -- For mTLS:
--   local client = http_client.new("https://example.com:8081", {
--     timeouts = {connect=1000, send=1000, read=1000},
--     ssl_verify = true,
--     ssl_client_cert = parsed_cert_cdata,  -- or "/path/to/cert.pem"
--     ssl_client_priv_key = parsed_key_cdata,  -- or "/path/to/key.pem"
--     use_tls_auth = true
--   })
--   
--   -- For Unix sockets:
--   local client = http_client.new("unix:/var/run/crowdsec.sock", {
--     timeouts = {connect=1000, send=1000, read=1000},
--     api_key = "your-api-key"
--   })
--   
--   -- Make requests - all complexity is handled automatically
--   local res, err = client:request_uri("/v1/decisions?ip=1.1.1.1", {
--     method = "GET",
--     headers = {["Custom-Header"] = "value"}
--   })

local http = require "resty.http"
local url = require "plugins.crowdsec.url"

local M = {}

-- Default API key header name
M.DEFAULT_API_KEY_HEADER = "X-Api-Key"

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
--   api_key: string - (optional) API key for authentication
--   api_key_header: string - (optional) Header name for API key (default: http_client.DEFAULT_API_KEY_HEADER)
--   user_agent: string - (optional) User-Agent header value
--   use_tls_auth: boolean - (optional) Whether to use TLS auth instead of API key
-- @return client: HTTP client object, or nil on error
-- @return err: Error message if failed
function M.new(url_str, options)
  options = options or {}
  
  -- Parse URL once
  local url_params, err = M.parse_url(url_str)
  if not url_params then
    return nil, err
  end
  
  -- Determine if using TLS auth (either explicitly set or inferred from cert/key presence)
  local use_tls_auth = options.use_tls_auth
  if use_tls_auth == nil then
    use_tls_auth = (options.ssl_client_cert ~= nil and options.ssl_client_priv_key ~= nil)
  end
  
  -- Build connection key with mTLS info if applicable
  local connection_key = url_params.connection_key
  if options.ssl_client_cert and options.ssl_client_priv_key then
    connection_key = connection_key .. "|mtls"
  end
  
  -- Validate and set timeouts (ensure they're numbers and positive)
  local timeouts = options.timeouts or {connect=3000, send=3000, read=3000}
  timeouts.connect = tonumber(timeouts.connect) or 3000
  timeouts.send = tonumber(timeouts.send) or 3000
  timeouts.read = tonumber(timeouts.read) or 3000
  
  -- Ensure timeouts are positive
  if timeouts.connect <= 0 then timeouts.connect = 3000 end
  if timeouts.send <= 0 then timeouts.send = 3000 end
  if timeouts.read <= 0 then timeouts.read = 3000 end
  
  -- Create client object (no httpc instance stored - created per request)
  local client = setmetatable({
    url_params = url_params,
    connection_key = connection_key,
    timeouts = timeouts,
    ssl_verify = options.ssl_verify ~= false,  -- default true
    ssl_client_cert = options.ssl_client_cert,
    ssl_client_priv_key = options.ssl_client_priv_key,
    keepalive_timeout = options.keepalive_timeout,
    keepalive_pool_size = options.keepalive_pool_size,
    api_key = options.api_key,
    api_key_header = options.api_key_header or M.DEFAULT_API_KEY_HEADER,
    user_agent = options.user_agent,
    use_tls_auth = use_tls_auth,
  }, Client)
  
  return client, nil
end

--- Prepare headers for request (internal method)
-- Automatically adds Host, User-Agent, and API key headers as needed
-- @param headers table: Existing headers (may be nil)
-- @return table: Headers with required fields added
function Client:_prepare_headers(headers)
  headers = headers or {}
  
  -- Set Host header appropriately for the connection type
  if not headers["Host"] and not headers["host"] then
    if self.url_params.is_unix then
      -- Unix sockets typically use localhost as Host header
      headers["Host"] = "localhost"
    else
      -- For HTTP/HTTPS, use the actual host and port (if non-standard)
      local host_header = self.url_params.host
      if self.url_params.port and 
         ((self.url_params.scheme == "http" and self.url_params.port ~= 80) or
          (self.url_params.scheme == "https" and self.url_params.port ~= 443)) then
        host_header = host_header .. ":" .. self.url_params.port
      end
      headers["Host"] = host_header
    end
  end
  
  -- Add User-Agent if configured
  if self.user_agent and not headers["User-Agent"] and not headers["user-agent"] then
    headers["User-Agent"] = self.user_agent
  end
  
  -- Add API key header if not using TLS auth
  if not self.use_tls_auth and self.api_key then
    headers[self.api_key_header] = self.api_key
  end
  
  -- Remove Connection: close header if present (we want keep-alive)
  headers["Connection"] = nil
  headers["connection"] = nil
  
  return headers
end

--- Create and connect HTTP client instance (internal method)
-- Following resty.http design: create, use, keepalive (don't store)
-- resty.http handles connection pooling internally via set_keepalive()
-- The connection details (unix/http/https, mTLS) are automatically handled
-- @return httpc: HTTP client object, or nil on error
-- @return err: Error message if failed
function Client:_create_httpc()
  -- Create new HTTP client instance (resty.http will reuse connections from pool)
  local httpc = http.new()
  
  -- Ensure timeouts are valid numbers before setting
  local connect_timeout = tonumber(self.timeouts.connect) or 3000
  local send_timeout = tonumber(self.timeouts.send) or 3000
  local read_timeout = tonumber(self.timeouts.read) or 3000
  
  -- Validate timeouts are positive
  if connect_timeout <= 0 then connect_timeout = 3000 end
  if send_timeout <= 0 then send_timeout = 3000 end
  if read_timeout <= 0 then read_timeout = 3000 end
  
  httpc:set_timeouts(connect_timeout, send_timeout, read_timeout)
  
  -- Build connection options - automatically handles unix/http/https
  local connect_opts = {}
  
  if self.url_params.is_unix then
    -- For Unix sockets, resty.http expects the full "unix:/path" in the host field
    -- Use connection_key which already contains "unix:/path"
    connect_opts.host = self.url_params.connection_key
    -- Explicitly set scheme and port to nil for Unix sockets (resty.http requirement)
    connect_opts.scheme = nil
    connect_opts.port = nil
  else
    -- For HTTP/HTTPS, use standard connection parameters
    connect_opts.scheme = self.url_params.scheme
    connect_opts.host = self.url_params.host
    connect_opts.port = self.url_params.port
  end
  
  -- SSL/TLS configuration
  connect_opts.ssl_verify = self.ssl_verify
  
  -- Add mTLS client certificates if configured
  if self.ssl_client_cert and self.ssl_client_priv_key then
    connect_opts.ssl_client_cert = self.ssl_client_cert
    connect_opts.ssl_client_priv_key = self.ssl_client_priv_key
  end
  
  -- Connect - resty.http will automatically reuse connections from its pool
  local ok, err = httpc:connect(connect_opts)
  if not ok then
    return nil, "Failed to connect: " .. (err or "unknown")
  end
  
  return httpc, nil
end

--- Release HTTP client back to keep-alive pool (internal method)
-- Uses resty.http's built-in connection pooling via set_keepalive
-- Following resty.http design: create, use, keepalive (don't store)
-- @param httpc: HTTP client instance to release
-- @return ok: boolean indicating success
-- @return err: Error message if failed
function Client:_release_httpc(httpc)
  if not httpc then
    return true, nil
  end
  
  -- Check if keepalive_timeout and keepalive_pool_size are set
  -- If not, just close the connection (no keep-alive)
  if not self.keepalive_timeout or not self.keepalive_pool_size then
    pcall(function() httpc:close() end)
    return true, nil
  end
  
  -- Try to set keepalive - use pcall to safely handle any errors
  local success, ok, err = pcall(function()
    return httpc:set_keepalive(self.keepalive_timeout, self.keepalive_pool_size)
  end)
  
  if not success then
    -- pcall failed - set_keepalive threw an error (ok contains the error message)
    pcall(function() httpc:close() end)
    return false, "Failed to set keepalive: " .. tostring(ok)
  end
  
  -- Check if set_keepalive returned success (ok is boolean, err is error message if failed)
  if not ok then
    -- set_keepalive returned false
    pcall(function() httpc:close() end)
    return false, "Failed to set keepalive: " .. (tostring(err) or "unknown")
  end
  
  -- After set_keepalive(), the httpc object is in a "closed" state but the connection
  -- is in resty.http's pool. resty.http will automatically reuse the underlying connection
  -- from its pool when we create a new httpc on the next request.
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

--- Build full URL for error messages
-- @param path string: Request path (may include query string)
-- @return string: Full URL including base URL and path
function Client:build_url(path)
  local full_path = self:_build_path(path)
  
  -- For Unix sockets, the full_url is "unix:/path/to/sock" and we append the HTTP path
  if self.url_params.is_unix then
    -- Extract the base socket path (everything before any HTTP path)
    local base_socket = self.url_params.full_url
    -- If the original URL had an HTTP path component, remove it
    local http_path_match = base_socket:match("(/v%d+/.*)$") or base_socket:match("(/api/.*)$")
    if http_path_match then
      base_socket = base_socket:sub(1, #base_socket - #http_path_match)
    end
    return base_socket .. full_path
  end
  
  -- For HTTP/HTTPS, construct from scheme, host, port, and path
  local base_url = self.url_params.scheme .. "://" .. self.url_params.host
  if self.url_params.port and 
     ((self.url_params.scheme == "http" and self.url_params.port ~= 80) or
      (self.url_params.scheme == "https" and self.url_params.port ~= 443)) then
    base_url = base_url .. ":" .. self.url_params.port
  end
  
  return base_url .. full_path
end

--- Make HTTP request with full control
-- All connection details (unix/http/https, mTLS) are handled automatically
-- @param client: Client object (self)
-- @param method string: HTTP method (GET, POST, etc.)
-- @param path string: Request path
-- @param headers table: HTTP headers (optional)
-- @param body string: (optional) Request body
-- @return res: HTTP response object with .status and .body, or nil on error
-- @return err: Error message if failed
function Client:request(method, path, headers, body)
  local full_url = self:build_url(path)
  
  -- Prepare headers (adds Host, User-Agent, API key automatically)
  -- This doesn't require a connection, so do it first
  headers = self:_prepare_headers(headers)
  
  -- Build full path (handles base path and query string merging)
  -- This doesn't require a connection, so do it before connecting
  local full_path = self:_build_path(path)
  
  -- Create and connect HTTP client (resty.http handles connection pooling)
  -- Only connect when we're ready to make the request
  local httpc, err = self:_create_httpc()
  if not httpc then
    return nil, "Failed to connect to " .. full_url .. ": " .. (err or "unknown")
  end

  -- Make request
  local res, err = httpc:request({
    method = method,
    path = full_path,
    headers = headers,
    body = body
  })
  
  if not res then
    -- Request failed, close connection
    pcall(function() httpc:close() end)
    return nil, "Request to " .. full_url .. " failed: " .. (err or "unknown")
  end
  
  -- Read response body
  local body_str, err = res:read_body()
  if err then
    -- Failed to read body, return error to caller
    -- Return connection to keep-alive pool before returning error
    self:_release_httpc(httpc)
    return nil, "Failed to read response body: " .. (err or "unknown")
  end
  
  res.body = body_str
  
  -- Return connection to keep-alive pool (resty.http handles pooling)
  self:_release_httpc(httpc)
  
  return res, nil
end

--- Make HTTP request using only the base path from URL (no additional path needed)
-- Useful for services like AppSec that always use the configured base path
-- All connection details are handled automatically
-- @param client: Client object (self)
-- @param options table: Request options:
--   method: string (default: "GET")
--   headers: table (HTTP headers, optional)
--   body: string (request body, optional)
-- @return res: HTTP response object with .status and .body, or nil on error
-- @return err: Error message if failed
function Client:request_base(options)
  return self:request_uri("", options)
end

--- Make HTTP request with path
-- All connection details (unix/http/https, mTLS) are handled automatically
-- @param client: Client object (self)
-- @param path string: Request path (can include query string)
-- @param options table: Request options:
--   method: string (default: "GET")
--   headers: table (HTTP headers, optional)
--   body: string (request body, optional)
-- @return res: HTTP response object with .status and .body, or nil on error
-- @return err: Error message if failed
function Client:request_uri(path, options)
  options = options or {}
  
  -- Use the unified request method which handles everything
  return self:request(
    options.method or "GET",
    path,
    options.headers,
    options.body
  )
end

return M
