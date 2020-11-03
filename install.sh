#!/usr/bin/env bash

LIB_PATH="/usr/local/lua/crowdsec/"

LAST_LUA_VERSION="5.3"
LUA_VERSIONS=(
    "5.0"
    "5.1"
    "5.2"
    "5.3"
)

DEPENDENCY=(
    "lua-sec"
)

check_lua() {
    found="false"
    for v in ${LUA_VERSIONS[@]};
    do
        which "lua${v}" > /dev/null && found="true"
    done

    if [[ "$found" = "false" ]]; then
        echo "lua not found, do you want to install it (Y/n)? "
        read answer
        if [[ ${answer} == "" ]]; then
            answer="y"
        fi
        if [ "$answer" != "${answer#[Yy]}" ] ;then
            apt-get install -y -qq "lua${LAST_LUA_VERSION}" > /dev/null && echo "lua${LAST_LUA_VERSION} successfully installed"
        else
            echo "unable to continue without lua. Exiting" && exit 1
        fi      
    fi
}

check_package_dependency() {
    for dep in ${DEPENDENCY[@]};
    do
        dpkg -l | grep ${dep} > /dev/null
        if [[ $? != 0 ]]; then
            echo "${dep} not found, do you want to install it (Y/n)? "
            read answer
            if [[ ${answer} == "" ]]; then
                answer="y"
            fi
            if [ "$answer" != "${answer#[Yy]}" ] ;then
                apt-get install -y -qq ${dep} > /dev/null && echo "${dep} successfully installed"
            else
                echo "unable to continue without ${dep}. Exiting" && exit 1
            fi      
        fi
    done
}

install_lib() {
   	mkdir -p ${LIB_PATH}
	cp lib/*.lua ${LIB_PATH}
}


check_lua
check_package_dependency
if [[ "$1" == "--dependency" ]];
then
    exit 0
fi
install_lib