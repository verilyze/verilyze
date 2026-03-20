_vlz() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="vlz"
                ;;
            vlz,config)
                cmd="vlz__config"
                ;;
            vlz,db)
                cmd="vlz__db"
                ;;
            vlz,fp)
                cmd="vlz__fp"
                ;;
            vlz,generate-completions)
                cmd="vlz__generate__completions"
                ;;
            vlz,help)
                cmd="vlz__help"
                ;;
            vlz,list)
                cmd="vlz__list"
                ;;
            vlz,preload)
                cmd="vlz__preload"
                ;;
            vlz,scan)
                cmd="vlz__scan"
                ;;
            vlz__db,list-providers)
                cmd="vlz__db__list__providers"
                ;;
            vlz__db,migrate)
                cmd="vlz__db__migrate"
                ;;
            vlz__db,set-ttl)
                cmd="vlz__db__set__ttl"
                ;;
            vlz__db,show)
                cmd="vlz__db__show"
                ;;
            vlz__db,stats)
                cmd="vlz__db__stats"
                ;;
            vlz__db,verify)
                cmd="vlz__db__verify"
                ;;
            vlz__fp,mark)
                cmd="vlz__fp__mark"
                ;;
            vlz__fp,unmark)
                cmd="vlz__fp__unmark"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        vlz)
            opts="-v -c -h -V --verbose --config --env-overrides --help --version scan list config db fp preload help generate-completions"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --env-overrides)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__config)
            opts="-c -h --list --example --set --config --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --set)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__db)
            opts="-c -h --cache-ttl-secs --config --help stats verify migrate list-providers show set-ttl"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cache-ttl-secs)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__db__list__providers)
            opts="-c -h --config --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__db__migrate)
            opts="-c -h --config --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__db__set__ttl)
            opts="-c -h --entry --all --pattern --entries --config --help <SECS>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --entry)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pattern)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --entries)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__db__show)
            opts="-c -h --format --full --config --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__db__stats)
            opts="-c -h --config --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__db__verify)
            opts="-c -h --config --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__fp)
            opts="-c -h --config --help mark unmark"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__fp__mark)
            opts="-c -h --comment --project-id --config --help <CVE-ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --comment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__fp__unmark)
            opts="-c -h --config --help <CVE-ID>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__generate__completions)
            opts="-c -h --config --help bash elvish fish powershell zsh"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__help)
            opts="-c -h --config --help [SUBCOMMAND]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__list)
            opts="-c -h --config --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__preload)
            opts="-c -h --config --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vlz__scan)
            opts="-c -h --format --summary-file --provider --parallel --cache-db --ignore-db --cache-ttl-secs --offline --benchmark --min-score --min-count --exit-code-on-cve --fp-exit-code --project-id --package-manager-required --backoff-base --backoff-max --max-retries --provider-http-connect-timeout-secs --provider-http-request-timeout-secs --severity-v2-critical-min --severity-v2-high-min --severity-v2-medium-min --severity-v2-low-min --severity-v3-critical-min --severity-v3-high-min --severity-v3-medium-min --severity-v3-low-min --severity-v4-critical-min --severity-v4-high-min --severity-v4-medium-min --severity-v4-low-min --config --help [PATH]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --summary-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --provider)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --parallel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cache-db)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ignore-db)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cache-ttl-secs)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-score)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-count)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --exit-code-on-cve)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fp-exit-code)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --project-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --backoff-base)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --backoff-max)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-retries)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --provider-http-connect-timeout-secs)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --provider-http-request-timeout-secs)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v2-critical-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v2-high-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v2-medium-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v2-low-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v3-critical-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v3-high-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v3-medium-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v3-low-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v4-critical-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v4-high-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v4-medium-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --severity-v4-low-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _vlz -o nosort -o bashdefault -o default vlz
else
    complete -F _vlz -o bashdefault -o default vlz
fi
