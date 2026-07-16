# Regression test for issue #145: EXCLUDE_LOCATION prefix matching.
# The client IP 1.1.1.1 is banned. EXCLUDE_LOCATION=/excluded, so:
#   GET /excluded         -> excluded (exact match)                     -> served (200)
#   GET /excluded/app.js  -> excluded (prefix match, THE FIX for #145)  -> served (200)
#   GET /excludedother    -> NOT excluded (/excluded/ boundary)         -> bounced (403)
#   GET /t                -> NOT excluded (proves the ban is active)    -> bounced (403)

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 22: EXCLUDE_LOCATION excludes exact match and sub-paths, but respects the location boundary

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
        local ok, err = cs.init("./t/conf_t/22_exclude_location_prefix_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
            local args, err = ngx.req.get_uri_args()
            if args.ip == "1.1.1.1" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"ban","value":"1.1.1.1"}]')
            else
               ngx.print('null')
            end
            }
      }
}


--- config

# prefix location: nginx routes /excluded, /excluded/app.js and /excludedother here
location /excluded {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.say("Hello, world")
    }
}

location = /t {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.say("Hello, world")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1
--- request eval
["GET /excluded", "GET /excluded/app.js", "GET /excludedother", "GET /t"]
--- error_code eval
[200, 200, 403, 403]
--- response_body_like eval
["Hello, world", "Hello, world", "Nope", "Nope"]
