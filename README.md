# lua-cs-bouncer

> Lua module to allow ip (or not) from CrowdSec API.

# Install & Config

`git clone https://github.com/crowdsecurity/lua-cs-bouncer.git`

## Install script

```
sudo ./install.sh
```
:warning: the installation script works only on Debian/Ubuntu

## From source

### Requirements

```
 apt-get install lua5.3
 apt-get install lua-sec
```

### With make
```
sudo make install
```

### Manually

- Create folder `/usr/local/lua/crowdsec/`:
```
mkdir -p /usr/local/lua/crowdsec/
```

- Copy the `lua-cs-bouncer/lib/*.lua` into `/usr/local/lua/crowdsec/`:
```
cp ./lua-cs-bouncer/lib/*.lua /usr/local/lua/crowdsec
```

- Copy the `lua-cs-bouncer/template.conf` into `/usr/local/lua/crowdsec/crowdsec.conf`:
```
cp ./lua-cs-bouncer/template.conf /usr/local/lua/crowdsec/crowdsec.conf
```

## Configuration

The configuration is located by default in `/usr/local/lua/crowdsec/crowdsec.conf`:

```
API_URL=http://localhost:8080                 <-- the API url
API_KEY=                                      <-- the API Key generated with `cscli bouncers add -n <bouncer_name>` 
LOG_FILE=/tmp/lua_mod.log                     <-- path to log file
CACHE_EXPIRATION=1                            <-- in seconds
CACHE_SIZE=1000                               <-- cache size
REQUEST_TIMEOUT=0.2                           <-- Maximum duration in seconds for a request to LAPI
```
