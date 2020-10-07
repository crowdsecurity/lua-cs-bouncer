LIB_PATH="/usr/local/lua/crowdsec/"
CROWDSEC_CONF="crowdsec.conf"

default: install
install: 
	@bash ./install.sh
	@mkdir -p $(LIB_PATH)
	@cp lib/*.lua $(LIB_PATH)
	@cp template.conf $(LIB_PATH)/$(CROWDSEC_CONF)

uninstall:
	@rm -rf $(LIB_PATH)