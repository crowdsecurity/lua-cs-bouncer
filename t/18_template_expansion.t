use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 18: Test template variable expansion on ban

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
        local ok, err = cs.init("./t/conf_t/18_template_test_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
                if ngx.var.unix == "1" then
                ngx.log(ngx.DEBUG, "[Crowdsec] Unix socket request ignoring...")
        else
                cs.Allow(ngx.var.remote_addr)
        end
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
--- request
GET /t
--- response_body_like
Banned
IP: 1\.1\.1\.1
ID: [a-f0-9-]+
Time: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}
No custom message
Details hidden

--- error_code: 403
