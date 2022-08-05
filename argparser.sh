#!/bin/bash

# Argbash - see https://argbash.io for more info
die() {
	local _ret="${2:-1}"
	test "${_PRINT_HELP:-no}" = yes && print_help >&2
	echo "$1" >&2
	exit "${_ret}"
}

print_help() {
    printf '%s\n'
    printf '%s\n' "Install and configure Zimbra 10.0 ..."
    printf 'Usage: %s [-c|--component <arg>] [-p|--password <arg>] [-t|--timezone <arg>] [-l|--letsencypt <arg>] [-h|--help] <domain>\n' "$(basename $0)"
    printf '\t%s\n' "<domain>: Domain to install Zimbra for"
    printf '\t%s\n' "-c, --component: Mandatory Component to install (ldap|mailstore|mtaproxy)"
    printf '\t%s\n' "-p, --password: Admin password to use (no default)"
    printf '\t%s\n' "-n, --hostname: Hostname to use for the server (default: mail)"
    printf '\t%s\n' "-t, --timezone: Timezone to set the server to user (optional) (default: 'Singapore')"
    printf '\t%s\n' "-l, --letsencypt: Use Let's Encrypt for providing TLS certificates (optional y/n) (default: 'n')"
    printf '\t%s\n' "-a, --apache: Add support for spell check and convertd (optional y/n) (default: 'n')"
    printf '\t%s\n' "-h, --help: Prints help"
    printf '%s\n'
    printf '%s\n' "Usage: $(basename $0) [-c ldap] [-p mypassword] [-t 'TimeZone'] [-n Server-Name] [-l y] Domain-Name"
    printf '%s\n' "Example: $(basename $0) -c ldap -n zmail -l y myorg.com"
    exit 1
}

parse_commandline() {
    _positionals_count=0
    while test $# -gt 0; do
        _key="$1"
        case "$_key" in
            -c|--component)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_component="$2"
                shift
                ;;
            --component=*)
                _arg_component="${_key##--component=}"
                ;;
            -c*)
                _arg_component="${_key##-p}"
                ;;
            -p|--password)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_password="$2"
                shift
                ;;
            --password=*)
                _arg_password="${_key##--password=}"
                ;;
            -p*)
                _arg_password="${_key##-p}"
                ;;
            -n|--hostname)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_hostname="$2"
                shift
                ;;
            --hostname=*)
                _arg_hostname="${_key##--hostname=}"
                ;;
            -n)
                _arg_hostname="${_key##-t}"
                ;;
            -t|--timezone)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_timezone="$2"
                shift
                ;;
            --timezone=*)
                _arg_timezone="${_key##--timezone=}"
                ;;
            -t*)
                _arg_timezone="${_key##-t}"
                ;;
            -a|--apache)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_apace="$2"
                shift
                ;;
            --apache=*)
                _arg_apache="${_key##--timezone=}"
                ;;
            -a*)
                _arg_apache="${_key##-t}"
                ;;
            -l|--letsencrypt)
                test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
                _arg_letsencrypt="$2"
                shift
                ;;
            --letsencrypt=*)
                _arg_letsencrypt="${_key##--letsencrypt=}"
                ;;
            -l*)
                _arg_letsencrypt="${_key##-l}"
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            -h*)
                print_help
                exit 0
                ;;
            *)
                _last_positional="$1"
                _positionals+=("$_last_positional")
                _positionals_count=$((_positionals_count + 1))
                ;;
        esac
        shift
    done
}

handle_passed_args_count() {
	local _required_args_string="'domain'"
	test "${_positionals_count}" -ge 1 || _PRINT_HELP=yes die "FATAL ERROR: Not enough positional arguments - we require exactly 1 (namely: $_required_args_string), but got only ${_positionals_count}." 1
	test "${_positionals_count}" -le 1 || _PRINT_HELP=yes die "FATAL ERROR: There were spurious positional arguments --- we expect exactly 1 (namely: $_required_args_string), but got ${_positionals_count} (the last one was: '${_last_positional}')." 1
}

assign_positional_args() {
	local _positional_name _shift_for=$1
	_positional_names="_arg_domain "

	shift "$_shift_for"
	for _positional_name in ${_positional_names}
	do
		test $# -gt 0 || break
		eval "$_positional_name=\${1}" || die "Error during argument parsing, possibly an Argbash bug." 1
		shift
	done
}

parse_commandline "$@"
handle_passed_args_count
assign_positional_args 1 "${_positionals[@]}"