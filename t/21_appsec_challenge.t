use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: AppSec 'challenge' remediation serves the challenge page, headers and cookie

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
        local ok, err = cs.init("./t/conf_t/21_appsec_challenge_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

server {
    listen 8081;

       location = /v1/decisions {
            content_by_lua_block {
                -- no local decision for the IP, so the request reaches AppSec
                ngx.print('null')
            }
       }
}

server {
    listen 7422;

       location / {
            content_by_lua_block {
                -- AppSec signals a remediation (403) and asks the bouncer to
                -- serve a challenge page verbatim with a 200 status.
                ngx.status = 403
                ngx.print([[{"action":"challenge","http_status":200,"user_body_content":"<html><body>cs-challenge-marker<script>console.log('cs')</script></body></html>","user_headers":{"Content-Type":["text/html"]},"user_cookies":["cs_challenge=abc123; Path=/; HttpOnly"]}]])
            }
       }
}


--- config


location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
    }
    content_by_lua_block {
        -- must never be reached: the challenge short-circuits the request
        ngx.say("Hello, world")
    }
}

--- raw_request eval
"GET /t HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 1.1.1.2\r\nConnection: close\r\n\r\n"

--- response_body eval
"<html><body>cs-challenge-marker<script>console.log('cs')</script></body></html>"
--- response_headers
Content-Type: text/html
Set-Cookie: cs_challenge=abc123; Path=/; HttpOnly
--- error_code: 200


=== TEST 2: AppSec 'challenge' remediation does not leak the protected content

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
        local ok, err = cs.init("./t/conf_t/21_appsec_challenge_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
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
                ngx.status = 403
                ngx.print([[{"action":"challenge","http_status":200,"user_body_content":"<html><body>cs-challenge-marker</body></html>","user_headers":{"Content-Type":["text/html"]},"user_cookies":["cs_challenge=abc123; Path=/; HttpOnly"]}]])
            }
       }
}


--- config


location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
    }
    content_by_lua_block {
        ngx.say("protected-origin-content")
    }
}

--- raw_request eval
"GET /t HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 1.1.1.3\r\nConnection: close\r\n\r\n"

--- response_body_unlike: protected-origin-content
--- error_code: 200
