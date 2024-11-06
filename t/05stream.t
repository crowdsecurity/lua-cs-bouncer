use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 5: Stream mode block test

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;


init_by_lua_block
{
        runner = require 'luacov.runner'
        runner.tick = true
        runner.init({statsfile = string.format("luacov_test4_%d_%s.stats.out", ngx.worker.id(), tostring(coroutine.running())), savestepsize = 20})
        jit.off()
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/05_stream_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        runner = require 'luacov.runner'
        runner.tick = true
        runner.init({statsfile = "prout", savestepsize = 1})
        jit.off()
        local cs = require "crowdsec"
        ngx.log(ngx.ERR,"Prout")
        cs.Allow(ngx.var.remote_addr)
}

server {
    listen 8081;

       location = /v1/decisions/stream {
            content_by_lua_block {
            local args, err = ngx.req.get_uri_args()
            if args.startup == "true" then
               ngx.say('{"deleted": [], "new": {"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"ban","value":"1.1.1.1"}}')
            else
               ngx.say('[{}]')
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
        ngx.say(ngx.var.remote_addr)
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.2
--- request
GET /t
--- error_code: 200

--- response_body eval
{
    sleep(20);
    return '';
}

--- delay: 15



--- more_headers
X-Forwarded-For: 1.1.1.1
--- request
GET /t
--- error_code: 403
