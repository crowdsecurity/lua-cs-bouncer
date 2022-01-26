local cs = require "crowdsec"

cs.Allow(ngx.var.remote_addr)
end
