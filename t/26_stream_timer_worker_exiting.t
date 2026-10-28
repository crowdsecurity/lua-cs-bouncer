use Test::Nginx::Socket 'no_plan';

master_on();
workers(1);
run_tests();

__DATA__

=== TEST 26: Stream refresh running when the worker exits

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config

lua_package_path './lib/?.lua;;';
lua_shared_dict crowdsec_cache 50m;
lua_shared_dict lapi_state 1m;

init_by_lua_block
{
        cs = require "crowdsec"
        local ok, err = cs.init("./t/conf_t/26_stream_timer_worker_exiting_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
}

init_worker_by_lua_block {
        cs = require "crowdsec"
        cs.SetupStream()
}

server {
    listen 8081;

      location = /v1/decisions/stream {
            content_by_lua_block {
            local args = ngx.req.get_uri_args()
            if args.startup ~= "true" then
               ngx.shared.lapi_state:set("refreshing", true)
               ngx.sleep(1)
            end
            ngx.say('{"deleted": [], "new": []}')
            }
      }
}

--- config

location = /t {
    content_by_lua_block {
        for _ = 1, 100 do
            if ngx.shared.lapi_state:get("refreshing") then
                break
            end
            ngx.sleep(0.1)
        end
        ngx.print(tostring(ngx.shared.lapi_state:get("refreshing")))
    }
}

--- request
GET /t
--- response_body: true
--- no_shutdown_error_log
Failed to create the timer
