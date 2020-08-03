#!/bin/bash

function retry_command {
    local usage="Usage: ${FUNCNAME[0]} [-b backoff-factor] [-d delay] [-n numtries]"
    local OPTIND OPTION
    local backoff_factor=2 delay=3 numtries=4

    while getopts ":b:d:n:" OPTION; do
        case "${OPTION}" in
        b)
            backoff_factor=${OPTARG}
            ;;
        d)
            delay=${OPTARG}
            ;;
        n)
            numtries=${OPTARG}
            ;;
        *)
            echo "$usage" 1>&2
            return 1
            ;;
        esac
    done
    shift $((OPTIND-1))

    exitcode=0
    while (( numtries > 0 )) ; do
        eval "$@"
        exitcode=$?
        (( exitcode == 0 )) && break
        (( --numtries > 0 )) && sleep $delay
        (( delay *= backoff_factor ))
    done

    return $exitcode
}

retry_command "$@"
