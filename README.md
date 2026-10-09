# lua-cs-bouncer

> Lua module to allow ip (or not) from CrowdSec API.

:warning: This library will only work with [lua-nginx-module](https://github.com/openresty/lua-nginx-module) 

This library is used by different bouncers : 

* [Nginx Bouncer](https://docs.crowdsec.net/docs/next/bouncers/nginx)
* [OpenResty Bouncer](https://docs.crowdsec.net/docs/next/bouncers/openresty)
* [Ingress Nginx Bouncer](https://docs.crowdsec.net/docs/next/bouncers/ingress-nginx)

### ALTCHA Assets Setup
Vendor Dependency
This provider requires the ALTCHA JavaScript widget file.

```bash
wget https://raw.githubusercontent.com/altcha-org/altcha/refs/heads/main/dist/main/altcha.min.js -O templates/altcha.min.js```


Configuration needed : 
CAPTCHA_PROVIDER=altcha
CAPTCHA_TEMPLATE_PATH=/var/lib/crowdsec/lua/templates/altcha.html
CAPTCHA_EXPIRATION=432000

Then you need to generate a random key et set SECRET_KEY var 
Example : 
```openssl rand -hex 32 ```