# a background request (Sec-Fetch-Mode other than navigate) must not replace
# the page the visitor navigated to before the captcha is solved

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 25: Stream mode captcha keeps the navigated page

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new;

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;

my $req = HTTP::Request->new(GET => 'http://127.0.0.1:1984/t');
$req->header('X-Forwarded-For' => '1.1.1.10');
my $resp = $ua->request($req);
if (!$resp->is_success) {
    print $out_fh "Initialization failed with HTTP code " . $resp->code . "\n";
    exit 1;
}

sleep(6);

$req = HTTP::Request->new(GET => 'http://127.0.0.1:1984/page');
$req->header('X-Forwarded-For' => '1.1.1.1');
$req->header('Sec-Fetch-Mode' => 'navigate');
$resp = $ua->request($req);
if (!$resp->is_success || $resp->decoded_content !~ /<title>CrowdSec Captcha<\/title>/i) {
    print $out_fh "Navigation did not get the captcha\n";
    exit 1;
}

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

location ~ ^/(?:t|page)$ {
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;
    content_by_lua_block {
        ngx.print("ok")
    }
    log_by_lua_block {
        print("DEBUG CACHE:captcha_1.1.1.1:" .. tostring(ngx.shared.crowdsec_cache:get("captcha_1.1.1.1")))
    }
}

--- more_headers
X-Forwarded-For: 1.1.1.1
Sec-Fetch-Mode: cors
--- request
GET /t

--- error_code: 200
--- grep_error_log eval
qr/DEBUG CACHE:captcha_1\.1\.1\.1:[^ ,]*/
--- grep_error_log_out
DEBUG CACHE:captcha_1.1.1.1:nil
DEBUG CACHE:captcha_1.1.1.1:/page
DEBUG CACHE:captcha_1.1.1.1:/page
--- wait: 1
