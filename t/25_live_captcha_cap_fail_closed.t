# Live mode, CAPTCHA_PROVIDER=cap, verification fails at the transport level.
#   --- init            GET /t   -> served the cap widget, primes the verify state
#   --- request         POST /t  -> siteverify answers 429 -> NOT let through
#
# The stub answers the way an nginx edge in front of cap does when limit_req trips:
# a 429 carrying an HTML error page rather than cap's JSON. Reusing conf 23, which
# is the same deployment; only the stub's behaviour differs.
#
# Cap is self-hosted and rate limited per client IP, so a visitor can provoke this
# response for themselves on demand. Treating it as a solve would let anyone skip
# the captcha for CAPTCHA_EXPIRATION by submitting junk with a spent rate limit
# bucket, so the response here must be the captcha page again, never a 302.

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 25: Live mode cap captcha fails closed when siteverify errors

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new;
my $url = 'http://127.0.0.1:1984/t';

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;
print $out_fh "Starting initialization...\n";

my $req = HTTP::Request->new(GET => $url);
$req->header('X-Forwarded-For' => '1.1.1.1');

my $resp = $ua->request($req);
if (!$resp->is_success || $resp->code != 200) {
    print $out_fh "Expected the captcha page, got HTTP " . $resp->code . "\n";
    exit 1;
}

if ($resp->decoded_content !~ /<title>CrowdSec Captcha<\/title>/i) {
    print $out_fh "Captcha template was not served\n";
    exit 1;
}

print $out_fh "Captcha page served as expected.\n";
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
        local ok, err = cs.init("./t/conf_t/23_live_captcha_cap_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
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

server {
    listen 8081;

      location = /v1/decisions {
            content_by_lua_block {
            local args, err = ngx.req.get_uri_args()
            if args.ip == "1.1.1.1" then
               ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"captcha","value":"1.1.1.1"}]')
            else
               ngx.say('[{}]')
            end
            }
      }

      # stub cap instance behind an edge whose rate limiter has tripped
      location = /capsitekey/siteverify {
            content_by_lua_block {
            ngx.status = 429
            ngx.header.content_type = "text/html"
            ngx.log(ngx.ALERT, "STUB SITEVERIFY: rate limited")
            ngx.say('<html><head><title>429 Too Many Requests</title></head><body></body></html>')
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
}

--- more_headers
X-Forwarded-For: 1.1.1.1
Content-Type: application/x-www-form-urlencoded

--- request eval
"POST /t
cap-response=capsitekey:redeemid:redeemsecret"

--- error_code: 200
--- response_body_like: cap-widget
--- error_log
cap returned a non-JSON response (HTTP 429)
Invalid captcha from 1.1.1.1
