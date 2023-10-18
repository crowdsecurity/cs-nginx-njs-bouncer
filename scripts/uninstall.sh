#!/bin/bash

DATA_PATH="/var/lib/crowdsec/njs/"

usage() {
      echo "Usage:"
      echo "    ./uninstall.sh -h                 Display this help message."
      echo "    ./uninstall.sh                    Uninstall the bouncer in interactive mode"
      echo "    ./uninstall.sh -y                 Uninstall the bouncer and accept everything"
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


remove_nginx_dependency() {
    DEPENDENCY=(
        "gettext-base"
        "nginx-module-njs"
    )
    for dep in ${DEPENDENCY[@]};
    do
        dpkg -l | grep ${dep} > /dev/null
        if [[ $? == 0 ]]; then
            if [[ ${SILENT} == "true" ]]; then
                sudo apt-get install -y -qq ${dep} > /dev/null && echo "${dep} successfully removed"
            else
                echo "${dep} found, do you want to remove it (Y/n)? "
                read answer
                if [[ ${answer} == "" ]]; then
                    answer="y"
                fi
                if [ "$answer" != "${answer#[Yy]}" ] ;then
                    apt-get remove --purge -y -qq ${dep} > /dev/null && echo "${dep} successfully removed"
                fi
            fi
        fi
    done
}


uninstall() {
    rm -r ${DATA_PATH}
}

if ! [ $(id -u) = 0 ]; then
    log_err "Please run the uninstall script as root or with sudo"
    exit 1
fi
requirement
remove_nginx_dependency
uninstall

echo "Please remove any crowdsec related configuration in your nginx configuration files."
echo "crowdsec-nginx-bouncer uninstalled successfully"