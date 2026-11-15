use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: the applied remediation is exposed in $crowdsec_remediation when it is defined

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_shared_dict remediations 1m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;


init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/27_remediation_variable_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
                local uri = ngx.req.get_headers()["x-crowdsec-appsec-uri"] or ""
                if string.find(uri, "^/captcha") ~= nil then
                    ngx.status = 403
                    ngx.print([[{"action":"captcha","http_status":403}]])
                elseif string.find(uri, "^/banned") ~= nil then
                    ngx.status = 403
                    ngx.print([[{"action":"ban","http_status":403}]])
                else
                    ngx.print([[{"action":"allow","http_status":200}]])
                end
            }
       }
}


--- config


location ~ ^/(t|captcha|banned)$ {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    set $crowdsec_remediation "";
    access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
    }
    content_by_lua_block {
        ngx.say("Hello, world")
    }
    log_by_lua_block {
        local seen = ngx.shared.remediations:get("seen") or ""
        ngx.shared.remediations:set("seen", seen .. ngx.var.uri .. "=" .. ngx.var.crowdsec_remediation .. ";")
    }
}

location = /peek {
    content_by_lua_block {
        ngx.say(ngx.shared.remediations:get("seen"))
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.20

--- pipelined_requests eval
[
    "GET /t",
    "GET /captcha",
    "GET /banned",
    "GET /peek",
]

--- error_code eval
[200, 200, 403, 200]

--- response_body_like eval
[
    "^Hello, world\$",
    "CrowdSec Captcha",
    "403 Forbidden",
    "^/t=;/captcha=captcha;/banned=ban;\$",
]
