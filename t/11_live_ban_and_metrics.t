# 4294967295 (0xffffffff) is the netmask as an int
# 16843009 (0x01010101) is the ip as an int
# metrics_processed are reset after 10s in this test

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 5: Stream mode block test

--- init

use LWP::UserAgent;

my $ua = LWP::UserAgent->new;
my $url = 'http://127.0.0.1:1984/t';

open my $out_fh, '>', 't/servroot/logs/perl.init.log' or die $!;
print $out_fh "Starting initialization...\n";

my $req = HTTP::Request->new(GET => $url);
$req->header('X-Forwarded-For' => '1.1.1.2');

my $resp = $ua->request($req);
if ($resp->is_success) {
    my $message = $resp->decoded_content;
    print $out_fh "Received reply: n\$message";
} else {
    print $out_fh "Initialization failed with HTTP code " . $resp->code . " and message: " . $resp->message . "\n";
    exit 1;
}

sleep(1);

$req = HTTP::Request->new(GET => $url);
$req->header('X-Forwarded-For' => '1.1.1.1');

$resp = $ua->request($req);
if (!$resp->is_success) {
   if ($resp->code == 403) {
        print $out_fh "Request forbidden with 403 as expected" . "\n";
   } else {
        print $out_fh "Initialization failed with HTTP code " . $resp->code . " and message: " . $resp->message . "\n";
        exit 1
   }
} else {
    my $message = $resp->decoded_content;
    print $out_fh "Received reply: $message\n" . " which should not happen";
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
        local ok, err = cs.init("./t/conf_t/11_live_crowdsec_nginx_bouncer.conf", "crowdsec-nginx-bouncer/v1.0.8")
        if ok == nil then
                ngx.log(ngx.ERR, "[Crowdsec] " .. err)
                error()
        end
        ngx.log(ngx.ALERT, "[Crowdsec] Initialisation done")
        -- shortening the metrics timer
        cs.debug_metrics()
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
           ngx.say('[{"duration":"1h00m00s","id":4091593,"origin":"CAPI","scenario":"crowdsecurity/vpatch-CVE-2024-4577","scope":"Ip","type":"ban","value":"1.1.1.1"}]')
         else
           ngx.print("null")
        end
        }
      }
      location = /v1/usage-metrics {
            content_by_lua_block {
                local cjson = require "cjson"
                ngx.req.read_body()
                local body = ngx.req.get_body_data()
                json = cjson.decode(body)
                print("EXTRACT METRICS JSON:" .. "type:" .. json["remediation_components"][1]["type"] .. " ")
                print("EXTRACT METRICS JSON:" .. "name:" .. json["remediation_components"][1]["name"] .. " ")
                print("EXTRACT METRICS JSON:" .. "window_size:" .. json["remediation_components"][1]["metrics"][1]["meta"]["window_size_seconds"] .. " ")
                -- three loops to ensure order
                for _, val in ipairs(json["remediation_components"][1]["metrics"][1]["items"]) do
                    if val["name"] == "processed" then
                         print("EXTRACT METRICS JSON:" .. val["name"] .. "/" .. val["unit"] .. "/" .. tostring(val["value"]) .. "/" .. val["labels"]["ip_type"] .. " ")
                    end
                end
                for _, val in ipairs(json["remediation_components"][1]["metrics"][1]["items"]) do
                    if val["name"] == "dropped" then
                         print("EXTRACT METRICS JSON:" .. val["name"] .. "/" .. val["unit"] .. "/" .. tostring(val["value"]) .. "/" .. val["labels"]["ip_type"] .. "/" .. val["labels"]["origin"] .. " ")
                    end
                end

                ngx.status = 201
                ngx.say("Created")
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

--- error_code: 403
--- grep_error_log eval
qr/EXTRACT METRICS JSON:[^ ]*/
--- grep_error_log_out
EXTRACT METRICS JSON:type:lua-bouncer
EXTRACT METRICS JSON:name:nginx
EXTRACT METRICS JSON:window_size:15
EXTRACT METRICS JSON:processed/request/3/ipv4
EXTRACT METRICS JSON:dropped/request/2/ipv4/CAPI
--- wait: 15
