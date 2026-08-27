use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: a body buffered to a temporary file is streamed to the AppSec in full

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;


init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/24_appsec_streamed_body_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
}

server {
    listen 8081;

       location = /v1/decisions {
            content_by_lua_block {
                ngx.print('null')
            }
       }
}

server {
    listen 7422;
    # the mock keeps what it receives in memory, we only care about what the bouncer sent
    client_body_buffer_size 1m;

       location / {
            content_by_lua_block {
                ngx.req.read_body()
                local body = ngx.req.get_body_data() or ""
                -- 'complete' tells us the announced content-length matches what really arrived,
                -- 'last' that we got the whole body, in order, up to its very last byte
                local announced = tonumber(ngx.var.http_content_length)
                local complete = (announced ~= nil and #body == announced) and "yes" or "no"
                ngx.log(ngx.ALERT, "appsec body: verb=" .. tostring(ngx.var.http_x_crowdsec_appsec_verb)
                    .. " te=" .. tostring(ngx.var.http_x_crowdsec_appsec_transfer_encoding)
                    .. " complete=" .. complete
                    .. " len=" .. #body
                    .. " last=" .. (#body > 0 and body:sub(-1) or "none"))
                ngx.status = 200
                ngx.print('{"action":"allow"}')
            }
       }
}


--- config

# force the request body out of memory and into a temporary file
client_body_buffer_size 1k;

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.say("Hello, world")
    }
}

--- raw_request eval
"POST /t HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 1.1.1.2\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n" . ("a" x 99999) . "Z"

--- response_body
Hello, world

--- error_log eval
qr/appsec body: verb=POST te=nil complete=yes len=100000 last=Z/

--- error_code: 200



=== TEST 2: a chunked body is announced with the length nginx decoded, not the client's

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;


init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/24_appsec_streamed_body_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
}

server {
    listen 8081;

       location = /v1/decisions {
            content_by_lua_block {
                ngx.print('null')
            }
       }
}

server {
    listen 7422;
    client_body_buffer_size 1m;

       location / {
            content_by_lua_block {
                ngx.req.read_body()
                local body = ngx.req.get_body_data() or ""
                local announced = tonumber(ngx.var.http_content_length)
                local complete = (announced ~= nil and #body == announced) and "yes" or "no"
                ngx.log(ngx.ALERT, "appsec body: verb=" .. tostring(ngx.var.http_x_crowdsec_appsec_verb)
                    .. " te=" .. tostring(ngx.var.http_x_crowdsec_appsec_transfer_encoding)
                    .. " complete=" .. complete
                    .. " len=" .. #body
                    .. " last=" .. (#body > 0 and body:sub(-1) or "none"))
                ngx.status = 200
                ngx.print('{"action":"allow"}')
            }
       }
}


--- config

client_body_buffer_size 1k;

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.say("Hello, world")
    }
}

--- raw_request eval
"POST /t HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 1.1.1.2\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
. "8000\r\n" . ("a" x 32768) . "\r\n"
. "1\r\nZ\r\n"
. "0\r\n\r\n"

--- response_body
Hello, world

--- error_log eval
qr/appsec body: verb=POST te=chunked complete=yes len=32769 last=Z/

--- error_code: 200



=== TEST 3: a body small enough to stay in memory is still forwarded as-is

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;


init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/24_appsec_streamed_body_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
}

server {
    listen 8081;

       location = /v1/decisions {
            content_by_lua_block {
                ngx.print('null')
            }
       }
}

server {
    listen 7422;
    client_body_buffer_size 1m;

       location / {
            content_by_lua_block {
                ngx.req.read_body()
                local body = ngx.req.get_body_data() or ""
                local announced = tonumber(ngx.var.http_content_length)
                local complete = (announced ~= nil and #body == announced) and "yes" or "no"
                ngx.log(ngx.ALERT, "appsec body: verb=" .. tostring(ngx.var.http_x_crowdsec_appsec_verb)
                    .. " te=" .. tostring(ngx.var.http_x_crowdsec_appsec_transfer_encoding)
                    .. " complete=" .. complete
                    .. " len=" .. #body
                    .. " last=" .. (#body > 0 and body:sub(-1) or "none"))
                ngx.status = 200
                ngx.print('{"action":"allow"}')
            }
       }
}


--- config

client_body_buffer_size 1k;

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.say("Hello, world")
    }
}

--- raw_request eval
"POST /t HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 1.1.1.2\r\nContent-Length: 100\r\nConnection: close\r\n\r\n" . ("a" x 99) . "Z"

--- response_body
Hello, world

--- error_log eval
qr/appsec body: verb=POST te=nil complete=yes len=100 last=Z/

--- error_code: 200
