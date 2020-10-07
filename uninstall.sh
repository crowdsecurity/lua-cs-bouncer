#!/usr/bin/env bash

LIB_PATH="/usr/local/lua/crowdsec/"
CROWDSEC_CONF="crowdsec.conf"

DEPENDENCY=(
    "lua-sec"
)

remove_package_dependency() {
    for dep in ${DEPENDENCY[@]};
    do
        dpkg -l | grep ${dep} > /dev/null
        if [[ $? == 0 ]]; then
            echo "${dep} found, do you want to remove it (Y/n)? "
            read answer
            if [[ ${answer} == "" ]]; then
                answer="y"
            fi
            if [ "$answer" != "${answer#[Yy]}" ] ;then
                apt-get remove --purge -y -qq ${dep} > /dev/null && echo "${dep} successfully removed"
            fi      
        fi
    done
}

uninstall_lib() {
    rm -rf ${LIB_PATH}
}


remove_package_dependency
uninstall_lib