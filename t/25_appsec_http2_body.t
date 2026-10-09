use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: the body of a HTTP/2+ request without content-length is forwarded when lua-nginx-module can read it

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
        local ok, err = cs.init("./t/conf_t/18_appsec_drop_unreadable_body_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        -- Simulate an HTTP/2+ request without content-length (the body is chunked)
        -- on a lua-nginx-module that is not 0.10.26.
        ngx.req.http_version = function() return 2.0 end
        ngx.config.ngx_lua_version = 10027
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

       location / {
            content_by_lua_block {
                ngx.req.read_body()
                local body = ngx.req.get_body_data() or ""
                ngx.log(ngx.ALERT, "appsec body: len=" .. #body .. " body=" .. body)
                ngx.status = 200
                ngx.print('{"action":"allow"}')
            }
       }
}


--- config


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
. "5\r\nhello\r\n"
. "0\r\n\r\n"

--- response_body
Hello, world

--- error_log eval
qr/appsec body: len=5 body=hello/

--- error_code: 200



=== TEST 2: the body of a HTTP/2+ gRPC request without content-length is not read

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
        local ok, err = cs.init("./t/conf_t/18_appsec_drop_unreadable_body_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        -- Simulate a HTTP/2+ gRPC request: its stream may never end, so the body
        -- must be considered unreadable even if lua-nginx-module could read it.
        ngx.req.http_version = function() return 2.0 end
        ngx.config.ngx_lua_version = 10027
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

       location / {
            content_by_lua_block {
                ngx.status = 200
                ngx.print('{"action":"allow"}')
            }
       }
}


--- config


location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.say("Hello, world")
    }
}

--- raw_request eval
"POST /t HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 1.1.1.2\r\nContent-Type: application/grpc+proto\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
. "5\r\nhello\r\n"
. "0\r\n\r\n"

--- error_log
Dropping request because body is unreadable and APPSEC_DROP_UNREADABLE_BODY is enabled

--- error_code: 403
