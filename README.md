# lua-cs-bouncer

> Lua module to allow ip (or not) from CrowdSec API.

# Install & Config

`git clone https://github.com/crowdsecurity/cs-lua-lib.git`

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

- Copy the `cs-lua-lib/lib/*.lua` into `/usr/local/lua/crowdsec/`:
```
cp ./cs-lua-lib/lib/*.lua /usr/local/lua/crowdsec
```

- Copy the `cs-lua-lib/template.conf` into `/usr/local/lua/crowdsec/crowdsec.conf`:
```
cp ./cs-lua-lib/template.conf /usr/local/lua/crowdsec/crowdsec.conf
```

## Configuration

The configuration is located by default in `/usr/local/lua/crowdsec/crowdsec.conf`:

```
API_URL=http://localhost:8080                 <-- the API url
API_KEY=                                      <-- the API Key generated with `cscli bouncers add -n <bouncer_name>` 
LOG_FILE=/tmp/lua_mod.log                     <-- path to log file
CACHE_EXPIRATION=1                            <-- in seconds
CACHE_SIZE=1000                               <-- cache size
```
