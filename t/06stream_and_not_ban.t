use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 6: Stream mode block test

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new;
my $url = 'http://127.0.0.1:1984/t';
my $req = HTTP::Request->new(GET => $url);

my $resp = $ua->request($req);

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;
select $out_fh;
$req->header('X-Forwarded-For' => '1.1.1.2');

if ($resp->is_success) {
    my $message = $resp->decoded_content;
    print "Received reply: $message";
}
else {
    print "Initialization failed with HTTP code " . $resp->code . " with " . $resp->message,
    exit 1
}
sleep(11)

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
        local ok, err = cs.init("./t/conf_t/05_stream_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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

init_worker_by_lua_block {
        cs = require "crowdsec"
        local mode = cs.get_mode()
        if string.lower(mode) == "stream" then
           ngx.log(ngx.INFO, "Initilizing stream mode for worker " .. tostring(ngx.worker.id()))
           cs.SetupStream()
        end

        if ngx.worker.id() == 0 then
           ngx.log(ngx.INFO, "Initilizing metrics for worker " .. tostring(ngx.worker.id()))
           cs.SetupMetrics()
        end
}

server {
    listen 8081;

       location = /v1/decisions/stream {
            content_by_lua_block {
            local args, err = ngx.req.get_uri_args()
            if args.startup == "true" then
               ngx.say('{"deleted": [], "new": [{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"ban","value":"1.1.1.1"}]}')
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
        ngx.print("ok")
    }
    log_by_lua_block {
        local cache = ngx.shared.crowdsec_cache
        local keys = cache:get_keys(0)
        for _, key in ipairs(keys) do
            ngx.log(ngx.DEBUG, "DEBUG CACHE:" .. key .. ":" .. tostring(cache:get(key)))
        end
    }

}

--- more_headers eval
["X-Forwarded-For: 1.1.1.1", "X-Forwarded-For: 1.1.1.2"]
--- pipelined_requests eval
["GET /t", "GET /t"]
--- error_code eval
[403, 200]
