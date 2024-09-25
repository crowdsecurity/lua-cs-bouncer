use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 2: lua configuration

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
        local ok, err = cs.init("./t/conf_t/04_stream_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
}

map $server_addr $unix {
        default       0;
        "~unix:" 1;
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
    location = /v1/decisions/stream {
    content_by_lua_block {
       data_startup = {
           new = {
                   {
                                           id = 0,
                                           duration = "1h",
                                           origin = "CAPI",
                                           scenario = "crowdsecurity/ssh-cve-2024-6387",
                                           scope = "Ip",
                                           type = "ban",
                                           value = "1.2.3.4",
                                         }
                                        }
                                      }

                                      data_cont = {
                                        new = {
                                         {
                                           id = 1,
                                           duration = "1h",
                                           origin = "CAPI",
                                           scenario = "crowdsecurity/ssh-cve-2024-6387",
                                           scope = "Ip",
                                           type = "ban",
                                           value = "5.6.7.8",
                                         }
                                        },
                                        deleted = {
                                         {
                                           id = 0,
                                           duration = "1h",
                                           origin = "CAPI",
                                           scenario = "crowdsecurity/ssh-cve-2024-6387",
                                           scope = "Ip",
	                                   type = "ban",
                                           value = "1.2.3.4",
                                         }

                                        }
                                      }

                                      local args, err = ngx.req.get_uri_args()
                                      ngx.log(ngx.ERR, "val:", args.startup)
                                      if args.startup == "true" then
                                         ngx.log(ngx.ERR, "called in startup mode")
                                         ngx.say(require "cjson".encode(data_startup))
                                      else
                                         ngx.log(ngx.ERR, "called in NON startup mode")
                                         ngx.say(require "cjson".encode(data_cont))
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
X-Forwarded-For: 1.2.3.4
--- request
GET /t
--- body_response
Nope
--- error_code: 403
