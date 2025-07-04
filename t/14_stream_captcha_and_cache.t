# 4294967295 (0xffffffff) is the netmask as an int
# 16843009 (0x01010101) is the ip as an int
# metrics_processed are reset after 10s in this test

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 14: Stream mode block test

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new;
my $url = 'http://127.0.0.1:1984/t';

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;
print $out_fh "Starting initialization...\n";

my $req = HTTP::Request->new(GET => $url);
$req->header('X-Forwarded-For' => '1.1.1.10');

my $resp = $ua->request($req);
if ($resp->is_success) {
    my $message = $resp->decoded_content;
    print $out_fh "Received reply: \n$message";
} else {
    print $out_fh "Initialization failed with HTTP code " . $resp->code . " and message: " . $resp->message . "\n";
    exit 1;
}

sleep(6);

$req = HTTP::Request->new(GET => $url);
$req->header('X-Forwarded-For' => '1.1.1.1');

$resp = $ua->request($req);
if ($resp->is_success) {
   if ($resp->code == 200) {
        print $out_fh "request authorized with 200 as expected" . "\n";
        my $content = $resp->decoded_content;
        if ($content =~ /<title>(.*?)<\/title>/i) {
            my $title = $1;
            if ($title eq "CrowdSec Captcha") {
                print $out_fh "Captcha as expected\n";
            } else {
                print $out_fh "Something is off with the captcha\n";
                exit 1;
            }
        } else {
           print $out_fh "Title tag not found\n";
           exit 1;
        }
   } else {
        print $out_fh "Initialization failed with HTTP code " . $resp->code . " and message: " . $resp->message . "\n";
        exit 1;
   }
} else {
    my $message = $resp->decoded_content;
    print $out_fh "Received reply: $resp->code\n" . " which should not happen";
    exit 1;
}
sleep(5);
print $out_fh "Initialization completed successfully.\n";
close $out_fh or warn "Could not close filehandle: $!";

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
        local ok, err = cs.init("./t/conf_t/14_stream_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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
               ngx.say('{"deleted": [], "new": [{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"1.1.1.1"}]}')
            else
               ngx.say('null')
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
        -- This dumps the crowdsec_cache to the error_log except for keys in the ignored_keys table
        -- Those keys depend on timestamp, let's handle separatly in other tests if needed
        ignored_keys = { "last_refresh", "metrics_startup_time", "metrics_data" }
        for _, key in ipairs(keys) do
            for _, ignored_key in ipairs(ignored_keys) do
                if key == ignored_key then
                   goto continue
                end
            end
            print("DEBUG CACHE:" .. key .. ":" .. tostring(cache:get(key)))
            ::continue::
        end
    }

}

--- more_headers
X-Forwarded-For: 1.1.1.1
--- request
GET /t

--- error_code: 200
--- grep_error_log eval
qr/DEBUG CACHE:[^ ]*/
--- grep_error_log_out
DEBUG CACHE:startup:true
DEBUG CACHE:first_run:true
DEBUG CACHE:metrics_first_run:false
DEBUG CACHE:metrics_processed/ip_type=ipv4&:1
DEBUG CACHE:metrics_all:processed/ip_type=ipv4&,
DEBUG CACHE:captcha_ok:true
DEBUG CACHE:first_run:true
DEBUG CACHE:metrics_first_run:false
DEBUG CACHE:startup:false
DEBUG CACHE:refreshing:false
DEBUG CACHE:metrics_processed/ip_type=ipv4&:2
DEBUG CACHE:decision_cache/ipv4_4294967295_16843009:captcha/CAPI/ipv4
DEBUG CACHE:metrics_dropped/ip_type=ipv4&origin=CAPI&:1
DEBUG CACHE:metrics_all:processed/ip_type=ipv4&,dropped/ip_type=ipv4&origin=CAPI&,
DEBUG CACHE:captcha_ok:true
DEBUG CACHE:captcha_1.1.1.1:/t
DEBUG CACHE:first_run:true
DEBUG CACHE:metrics_first_run:false
DEBUG CACHE:refreshing:true
DEBUG CACHE:startup:false
DEBUG CACHE:metrics_processed/ip_type=ipv4&:3
DEBUG CACHE:decision_cache/ipv4_4294967295_16843009:captcha/CAPI/ipv4
DEBUG CACHE:metrics_dropped/ip_type=ipv4&origin=CAPI&:2
DEBUG CACHE:metrics_all:processed/ip_type=ipv4&,dropped/ip_type=ipv4&origin=CAPI&,
DEBUG CACHE:captcha_ok:true
DEBUG CACHE:captcha_1.1.1.1:/t
--- wait: 1
