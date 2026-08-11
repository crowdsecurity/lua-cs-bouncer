# Live mode, CAPTCHA_PROVIDER=cap.
#   --- init            GET /t   -> served the cap widget, primes the verify state
#   --- request         POST /t  -> token verified against the stub siteverify -> 302
#
# The stub on 8081 mirrors cap's contract (standalone/src/siteverify.js): it answers
# {"success":true} only for a JSON body carrying the configured secret.

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 23: Live mode cap captcha

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

my $content = $resp->decoded_content;

if ($content !~ /<title>CrowdSec Captcha<\/title>/i) {
    print $out_fh "Captcha template was not served\n";
    exit 1;
}

# the widget must be a cap-widget pointed at the public endpoint, not the verify one
if ($content !~ m{<cap-widget id="captcha" data-cap-api-endpoint="https://cap\.example\.com/capsitekey/"}) {
    print $out_fh "cap-widget missing or wrong api endpoint\n";
    exit 1;
}

# the hidden input name must match what GetCaptchaBackendKey() reads back
if ($content !~ m{data-cap-hidden-field-name="cap-response"}) {
    print $out_fh "cap-widget is not renaming its hidden field to cap-response\n";
    exit 1;
}

# cap-widget is an ES module, a plain script tag would never define the element
if ($content !~ m{<script type="module" src="https://cdn\.jsdelivr\.net/npm/cap-widget\@}) {
    print $out_fh "widget script tag is missing type=module\n";
    exit 1;
}

if ($content =~ /\{\{/) {
    print $out_fh "template still contains unsubstituted placeholders\n";
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

      # stub cap instance
      location = /capsitekey/siteverify {
            content_by_lua_block {
            local cjson = require "cjson"
            ngx.req.read_body()
            local body = ngx.req.get_body_data()
            local ok, payload = pcall(cjson.decode, body)
            if not ok or payload.secret ~= "capsecret" or payload.response == nil then
               ngx.log(ngx.ERR, "STUB SITEVERIFY: rejected body " .. tostring(body))
               ngx.status = 400
               ngx.say('{"success":false,"error":"Missing required parameters"}')
               return
            end
            ngx.log(ngx.ALERT, "STUB SITEVERIFY: accepted response=" .. payload.response)
            ngx.say('{"success":true}')
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

--- error_code: 302
--- response_headers
Location: /t
--- grep_error_log eval
qr/STUB SITEVERIFY: [^,]*/
--- grep_error_log_out
STUB SITEVERIFY: accepted response=capsitekey:redeemid:redeemsecret
