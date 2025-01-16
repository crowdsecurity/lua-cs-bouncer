use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 5: Stream mode block test

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new;
my $url = 'http://127.0.0.1:1984/t';

my $req = HTTP::Request->new(GET => $url);
open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;
select $out_fh;
$req->header('X-Forwarded-For' => '1.1.1.1');

my $resp = $ua->request($req);
if ($resp->is_success) {
    my $message = $resp->decoded_content;
    die "Received reply: $message";
}
else {
    die "Initialization failed with HTTP code " . $resp->code " with " . $resp->message,
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

server {
    listen 8081;

       location = /v1/decisions/stream {
            content_by_lua_block {
            local args, err = ngx.req.get_uri_args()
            if args.startup == "true" then
               ngx.say('{"deleted": [], "new": [{"duration":"0h0m02s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"ban","value":"1.1.1.1"}]}')
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
}

--- more_headers
X-Forwarded-For: 1.1.1.1
--- request
GET /t
--- error_code: 200
