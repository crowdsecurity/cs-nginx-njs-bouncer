#!/bin/bash

CROWDSEC_NGINX_ROOT_CONF="crowdsec_root.conf"
CONFIG_PATH="/etc/crowdsec/bouncers/"
CONFIG_FILE_NAME="crowdsec-nginx-njs-bouncer.json"
LAPI_DEFAULT_PORT="8080"
SILENT="false"
DATA_PATH="/var/lib/crowdsec/njs/"

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit 1
    fi
}

usage() {
      echo "Usage:"
      echo "    ./install.sh -h                 Display this help message."
      echo "    ./install.sh                    Install the bouncer in interactive mode"
      echo "    ./install.sh -y                 Install the bouncer and accept everything"
      exit 0  
}


#Accept cmdline arguments to overwrite options.
while [[ $# -gt 0 ]]
do
    case $1 in
        -y|--yes)
            SILENT="true"
            shift
        ;;
        -h|--help)
            usage
        ;;
    esac
    shift
done


gen_apikey() {
    type cscli > /dev/null
    if [ "$?" -eq "0" ] ; then
        SUFFIX=`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
        API_KEY=`cscli bouncers add crowdsec-nginx-njs-bouncer-${SUFFIX} -o raw`
        PORT=$(cscli config show --key "Config.API.Server.ListenURI"|cut -d ":" -f2)
        if [ ! -z "$PORT" ]; then
            LAPI_DEFAULT_PORT=${PORT}
        fi
        echo "Bouncer registered to the CrowdSec Local API."
    else
        echo "cscli is not present, unable to register the bouncer to the CrowdSec Local API."
    fi
    CROWDSEC_LAPI_URL="http://127.0.0.1:${LAPI_DEFAULT_PORT}"
    mkdir -p "${CONFIG_PATH}"
    API_KEY=${API_KEY} CROWDSEC_LAPI_URL=${CROWDSEC_LAPI_URL} envsubst < ./conf/${CONFIG_FILE_NAME} | tee "${CONFIG_PATH}${CONFIG_FILE_NAME}" >/dev/null
}

check_nginx_dependency() {
    DEPENDENCY=(
        "gettext-base"
        "nginx-module-njs"
    )
    for dep in ${DEPENDENCY[@]};
    do
        dpkg -l | grep ${dep} > /dev/null
        if [[ $? != 0 ]]; then
            if [[ ${SILENT} == "true" ]]; then
                apt-get install -y -qq ${dep} > /dev/null && echo "${dep} successfully installed"
            else
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
        fi
    done
}


install() {
    mkdir -p ${DATA_PATH}
    cp -r ./crowdsec.js ./templates ./conf ${DATA_PATH}
    mv ${DATA_PATH}/conf/${CROWDSEC_NGINX_ROOT_CONF} /etc/nginx/conf.d/
}

check_root
check_nginx_dependency
gen_apikey
install


echo "crowdsec-nginx-njs-bouncer installed successfully"