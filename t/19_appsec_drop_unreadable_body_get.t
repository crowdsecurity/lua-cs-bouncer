use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: APPSEC_DROP_UNREADABLE_BODY=true does not drop GET requests (no body expected)

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
        -- Simulate an HTTP/2+ request so the missing content-length would
        -- normally be flagged as unreadable; since the method is GET, the
        -- request must still go through.
        ngx.req.http_version = function() return 2.0 end
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

--- more_headers
X-Forwarded-For: 1.1.1.2

--- request
GET /t

--- response_body
Hello, world

--- error_code: 200
