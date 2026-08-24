use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: an AppSec 'captcha' can be solved: the answer is validated and the IP gets a grace period

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
        local ok, err = cs.init("./t/conf_t/23_appsec_captcha_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        -- stub the captcha provider: the test must not reach out to a real one
        local captcha = require "plugins.crowdsec.captcha"
        captcha.Validate = function(captcha_res, remote_ip)
                return captcha_res == "valid-token", nil
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
                local uri = ngx.req.get_headers()["x-crowdsec-appsec-uri"] or ""
                ngx.status = 403
                if string.find(uri, "^/banned") ~= nil then
                    ngx.print([[{"action":"ban","http_status":403}]])
                else
                    -- the rule keeps matching on /t: this is what used to loop forever
                    ngx.print([[{"action":"captcha","http_status":403}]])
                end
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
        ngx.say("Hello, world")
    }
}

location = /banned {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    access_by_lua_block {
        local cs = require "crowdsec"
        cs.Allow(ngx.var.remote_addr)
    }
    content_by_lua_block {
        ngx.say("Hello, world")
    }
}

location = /peek {
    content_by_lua_block {
        local flag = require "plugins.crowdsec.flag"
        local uri, flags = ngx.shared.crowdsec_cache:get("captcha_" .. ngx.var.arg_ip)
        local source, state = flag.GetFlags(flags)
        ngx.say(tostring(uri) .. "|" .. flag.Flags[source] .. "|" .. flag.Flags[state])
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.20
Content-Type: application/x-www-form-urlencoded

--- pipelined_requests eval
[
    "GET /t",
    "GET /peek?ip=1.1.1.20",
    "POST /t\ng-recaptcha-response=valid-token",
    "GET /peek?ip=1.1.1.20",
    "GET /t",
    "GET /banned",
]

--- error_code eval
[200, 200, 302, 200, 200, 403]

--- response_body_like eval
[
    "CrowdSec Captcha",
    "^/t\\|appsec\\|to_verify\$",
    "302 Found",
    "^/t\\|appsec\\|validated\$",
    "^Hello, world\$",
    "403 Forbidden",
]


=== TEST 2: a wrong answer to an AppSec 'captcha' serves the captcha again

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
        local ok, err = cs.init("./t/conf_t/23_appsec_captcha_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        local captcha = require "plugins.crowdsec.captcha"
        captcha.Validate = function(captcha_res, remote_ip)
                return captcha_res == "valid-token", nil
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
                ngx.print([[{"action":"captcha","http_status":403}]])
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
        ngx.say("Hello, world")
    }
}

location = /peek {
    content_by_lua_block {
        local flag = require "plugins.crowdsec.flag"
        local uri, flags = ngx.shared.crowdsec_cache:get("captcha_" .. ngx.var.arg_ip)
        local source, state = flag.GetFlags(flags)
        ngx.say(tostring(uri) .. "|" .. flag.Flags[source] .. "|" .. flag.Flags[state])
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.21
Content-Type: application/x-www-form-urlencoded

--- pipelined_requests eval
[
    "GET /t",
    "POST /t\ng-recaptcha-response=nope",
    "GET /peek?ip=1.1.1.21",
]

--- error_code eval
[200, 200, 200]

--- response_body_like eval
[
    "CrowdSec Captcha",
    "CrowdSec Captcha",
    "^/t\\|appsec\\|to_verify\$",
]


=== TEST 3: a captcha solved for the AppSec does not satisfy a LAPI captcha decision

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
        local ok, err = cs.init("./t/conf_t/23_appsec_captcha_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
                ngx.print('[{"duration":"1h00m00s","id":1,"origin":"cscli","scenario":"manual","scope":"Ip","type":"captcha","value":"1.1.1.22"}]')
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
        ngx.say("Hello, world")
    }
}

location = /seed {
    content_by_lua_block {
        local flag = require "plugins.crowdsec.flag"
        local bit
        if _VERSION == "Lua 5.1" then bit = require "bit" else bit = require "bit32" end
        local source = flag.BOUNCER_SOURCE
        if ngx.var.arg_source == "appsec" then
            source = flag.APPSEC_SOURCE
        end
        ngx.shared.crowdsec_cache:set("captcha_" .. ngx.var.arg_ip, "/t", 3600, bit.bor(flag.VALIDATED_STATE, source))
        ngx.say("seeded")
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.22

--- pipelined_requests eval
[
    "GET /seed?ip=1.1.1.22&source=appsec",
    "GET /t",
    "GET /seed?ip=1.1.1.22&source=bouncer",
    "GET /t",
]

--- error_code eval
[200, 200, 200, 200]

--- response_body_like eval
[
    "^seeded\$",
    "CrowdSec Captcha",
    "^seeded\$",
    "^Hello, world\$",
]


=== TEST 4: a captcha state coming from a LAPI decision is still dropped once the IP is allowed

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
        local ok, err = cs.init("./t/conf_t/23_appsec_captcha_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
                -- AppSec is happy with the request
                ngx.status = 200
                ngx.print('')
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
        ngx.say("Hello, world")
    }
}

location = /seed {
    content_by_lua_block {
        local flag = require "plugins.crowdsec.flag"
        local bit
        if _VERSION == "Lua 5.1" then bit = require "bit" else bit = require "bit32" end
        local source = flag.BOUNCER_SOURCE
        if ngx.var.arg_source == "appsec" then
            source = flag.APPSEC_SOURCE
        end
        ngx.shared.crowdsec_cache:set("captcha_" .. ngx.var.arg_ip, "/t", 3600, bit.bor(flag.VALIDATED_STATE, source))
        ngx.say("seeded")
    }
}

location = /peek {
    content_by_lua_block {
        local flag = require "plugins.crowdsec.flag"
        local uri, flags = ngx.shared.crowdsec_cache:get("captcha_" .. ngx.var.arg_ip)
        local source, state = flag.GetFlags(flags)
        ngx.say(tostring(uri) .. "|" .. flag.Flags[source] .. "|" .. flag.Flags[state])
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.23

--- pipelined_requests eval
[
    "GET /seed?ip=1.1.1.23&source=bouncer",
    "GET /t",
    "GET /peek?ip=1.1.1.23",
    "GET /seed?ip=1.1.1.23&source=appsec",
    "GET /t",
    "GET /peek?ip=1.1.1.23",
]

--- error_code eval
[200, 200, 200, 200, 200, 200]

--- response_body_like eval
[
    "^seeded\$",
    "^Hello, world\$",
    "^nil\\|\\|\$",
    "^seeded\$",
    "^Hello, world\$",
    "^/t\\|appsec\\|validated\$",
]
