use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: Load lua configuration

--- main_config
load_module /usr/share/nginx/modules/ndk_http_module.so;
load_module /usr/share/nginx/modules/ngx_http_lua_module.so;

--- http_config
lua_package_path "./lib/?.lua;;";
lua_shared_dict crowdsec_cache 50m;

#  luacov -r lcov
#  genhtml luacov.report.out -o destination_directory/
init_by_lua_block {
        runner = require 'luacov.runner'
        runner.tick = true
        runner.init({statsfile = string.format("luacov_test1_%s.stats.out", ngx.worker.id()), savestepsize = 10})
        jit.off()
        cs = require "crowdsec"
        local ok, err = cs.init("t/conf_t/01_conf_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

access_by_lua_block {
        local cs = require "crowdsec"
        if ngx.var.unix == "1" then
                ngx.log(ngx.DEBUG, "[Crowdsec] Unix socket request ignoring...")
        else
                cs.Allow(ngx.var.remote_addr)
        end
}
--- config
location = /t {
    content_by_lua_block {
        ngx.say("hello, world")
    }
}
--- request
GET /t
--- response_body
hello, world
--- error_code: 200
