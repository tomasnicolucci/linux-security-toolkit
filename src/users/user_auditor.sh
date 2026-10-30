#!/usr/bin/env bash
#
# Linux User Auditor - Linux Security Toolkit, module 8.
#
# Read-only audit of user accounts, groups, privileges and the
# configuration files that control them. It never modifies the system,
# never runs commands as other users and never tries to crack passwords.
#
# Requires Bash 4.4 or newer and GNU coreutils. Run it as root to audit
# password data (/etc/shadow). See --help.

set -u
set -o pipefail

readonly VERSION="1.0.0"
readonly PROGRAM="user_auditor.sh"

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    printf 'Error: Bash 4.4 or newer is required.\n' >&2
    exit 2
fi

export LC_ALL=C
export TZ=UTC

# --------------------------------------------------------------------
# Options
# --------------------------------------------------------------------

ROOT="/"
MIN_SEVERITY="LOW"
FAIL_ON=""
JSON_PATH=""
SHOW_HASHES=0
CHECK_PERMISSIONS=1
CHECK_HOMES="auto"
CHECK_ACTIVITY="auto"
INACTIVE_DAYS=90
ALL_ACCOUNTS=0
MAX_PASSWORD_AGE=365
USE_COLOR="auto"

# Dangerous commands when allowed through sudo (shell escapes).
readonly DANGEROUS_COMMANDS=" sh bash dash zsh ksh csh tcsh fish su vi vim view nano ed less more man pico emacs awk gawk mawk nawk perl python python2 python3 ruby php lua node env find xargs tar zip unzip cp mv dd chmod chown chgrp rsync git ftp nmap tcpdump strace gdb docker "

# Groups whose members are effectively root.
readonly ROOT_EQUIVALENT_GROUPS=(docker lxd disk shadow)

# --------------------------------------------------------------------
# State
# --------------------------------------------------------------------

declare -a USERS=() GROUP_NAMES=() WARNINGS=() ERRORS=()
declare -a F_SEV=() F_ID=() F_SUBJECT=() F_TITLE=() F_DETAIL=() F_REC=()

declare -A PW_PASS=() PW_UID=() PW_GID=() PW_GECOS=() PW_HOME=() PW_SHELL=()
declare -A SH_HASH=() SH_LASTCHG=() SH_MAX=() SH_EXPIRE=()
declare -A GR_GID=() GR_MEMBERS=()
declare -A UID_OWNERS=() GID_OWNERS=() FIRST_USER_OF_UID=() FIRST_GROUP_OF_GID=() GID_PRIMARY_USERS=()
declare -A LOGIN_DEFS=() SSHD=()
declare -A ACC_STATE=() ACC_SOURCE=() ACC_ALGO=() ACC_WEAK=() ACC_HASH=() ACC_TYPE=() ACC_LOGIN=()
declare -A SUDO_LEVEL=() USER_GROUPS=() KEY_COUNT=()
declare -A SEV_NUM=([CRITICAL]=4 [HIGH]=3 [MEDIUM]=2 [LOW]=1)
declare -A UALIAS=() CALIAS=() SEEN_FILES=() WARNED=()
declare -a R_PRINC=() R_RUNAS_ROOT=() R_NOPASS=() R_CMD=() R_SRC=()

SHADOW_LOADED=0
GROUP_LOADED=0
SUDOERS_LOADED=0
SUDO_EVERYONE=0
UID_MIN=1000
UID_MAX=60000
NOW=0
TODAY=0
HOST_NAME=""
STARTED_AT=""
HOMES_CHECKED=0
ACTIVITY_CHECKED=0
EXP_ALL=0
declare -a EXP_USERS=() EXP_GROUPS=() CMD_LIST=() MEMBERS=()
REPLY=""
H_STATE="" H_ALGO="" H_WEAK=0 H_RAW=""
J=""

# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------

usage() {
    cat <<EOF
Linux User Auditor $VERSION

Read-only audit of user accounts, groups, sudo privileges, password
policy and related files. Run as root to include password data.

Usage: $PROGRAM [options]

Options:
  --root PATH               Audit the file tree under PATH (default: /).
                            Use /host for a mounted host, or a sample tree.
  --min-severity LEVEL      Show findings at or above LOW|MEDIUM|HIGH|CRITICAL
                            (default: LOW).
  --fail-on LEVEL           Exit with status 1 when a finding at or above
                            LEVEL exists (useful for cron and monitoring).
  --show-hashes             Print password hashes found in /etc/passwd and
                            /etc/shadow. SENSITIVE: they also go into the
                            JSON report, which is then created with mode 600.
  --all-accounts            List every account (default: regular accounts,
                            accounts with a login shell and privileged ones).
  --max-password-age DAYS   Report passwords older than DAYS (default: 365).
  --no-permission-checks    Skip file permission checks (use it with sample
                            trees, whose permissions are not meaningful).
  --check-homes             Check home directories, SSH keys and legacy trust
                            files. Enabled automatically when --root is /.
  --check-activity          Report accounts that never logged in or have been
                            inactive, using lastlog. Enabled automatically
                            when --root is / and lastlog is available.
  --inactive-days DAYS      Inactivity threshold (default: 90).
  --json PATH               Save the audit as JSON.
  --no-color                Disable colors.
  --version                 Show the version.
  -h, --help                Show this help.

Exit status: 0 audit completed, 1 findings reached --fail-on, 2 error.
EOF
}

die() {
    printf 'Error: %s\n' "$1" >&2
    exit 2
}

usage_error() {
    printf 'Error: %s\nTry %s --help.\n' "$1" "$PROGRAM" >&2
    exit 2
}

trim() {
    local s=$1
    s=${s#"${s%%[![:space:]]*}"}
    s=${s%"${s##*[![:space:]]}"}
    REPLY=$s
}

# Path of a file inside the audited tree.
p() {
    printf '%s/%s' "$ROOT" "${1#/}"
}

is_int() {
    [[ $1 =~ ^[0-9]+$ ]]
}

sev_value() {
    case $1 in
        CRITICAL) printf 4 ;;
        HIGH) printf 3 ;;
        MEDIUM) printf 2 ;;
        LOW) printf 1 ;;
        *) printf 0 ;;
    esac
}

sevn() {
    SEVN=${SEV_NUM[$1]:-0}
}

add_finding() {
    # severity id subject title detail recommendation
    F_SEV+=("$1")
    F_ID+=("$2")
    F_SUBJECT+=("$3")
    F_TITLE+=("$4")
    F_DETAIL+=("$5")
    F_REC+=("$6")
}

warn_once() {
    [[ -n ${WARNED[$1]+x} ]] && return
    WARNED[$1]=1
    WARNINGS+=("$1")
}

valid_name() {
    [[ $1 =~ ^[A-Za-z0-9_][A-Za-z0-9_.@\$-]*$ ]]
}

format_days() {
    # days since epoch -> YYYY-MM-DD (result in FDAYS)
    if is_int "$1"; then
        printf -v FDAYS '%(%Y-%m-%d)T' $(( 10#$1 * 86400 ))
    else
        FDAYS="-"
    fi
}

# --------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------

parse_args() {
    while (( $# )); do
        case $1 in
            --root) (( $# >= 2 )) || usage_error "--root requires a value."; ROOT=$2; shift 2 ;;
            --root=*) ROOT=${1#*=}; shift ;;
            --min-severity) (( $# >= 2 )) || usage_error "--min-severity requires a value."; MIN_SEVERITY=${2^^}; shift 2 ;;
            --min-severity=*) MIN_SEVERITY=${1#*=}; MIN_SEVERITY=${MIN_SEVERITY^^}; shift ;;
            --fail-on) (( $# >= 2 )) || usage_error "--fail-on requires a value."; FAIL_ON=${2^^}; shift 2 ;;
            --fail-on=*) FAIL_ON=${1#*=}; FAIL_ON=${FAIL_ON^^}; shift ;;
            --max-password-age) (( $# >= 2 )) || usage_error "--max-password-age requires a value."; MAX_PASSWORD_AGE=$2; shift 2 ;;
            --max-password-age=*) MAX_PASSWORD_AGE=${1#*=}; shift ;;
            --json) (( $# >= 2 )) || usage_error "--json requires a value."; JSON_PATH=$2; shift 2 ;;
            --json=*) JSON_PATH=${1#*=}; shift ;;
            --show-hashes) SHOW_HASHES=1; shift ;;
            --all-accounts) ALL_ACCOUNTS=1; shift ;;
            --no-permission-checks) CHECK_PERMISSIONS=0; shift ;;
            --check-homes) CHECK_HOMES=1; shift ;;
            --check-activity) CHECK_ACTIVITY=1; shift ;;
            --inactive-days) (( $# >= 2 )) || usage_error "--inactive-days requires a value."; INACTIVE_DAYS=$2; shift 2 ;;
            --inactive-days=*) INACTIVE_DAYS=${1#*=}; shift ;;
            --no-color) USE_COLOR=0; shift ;;
            --version) printf '%s %s\n' "$PROGRAM" "$VERSION"; exit 0 ;;
            -h|--help) usage; exit 0 ;;
            *) usage_error "Unknown option: $1" ;;
        esac
    done

    [[ -d $ROOT ]] || usage_error "--root is not a directory: $ROOT"
    ROOT=${ROOT%/}

    (( $(sev_value "$MIN_SEVERITY") > 0 )) || usage_error "Invalid --min-severity: $MIN_SEVERITY"

    if [[ -n $FAIL_ON ]] && (( $(sev_value "$FAIL_ON") == 0 )); then
        usage_error "Invalid --fail-on: $FAIL_ON"
    fi

    is_int "$MAX_PASSWORD_AGE" || usage_error "--max-password-age must be a number of days."
    is_int "$INACTIVE_DAYS" || usage_error "--inactive-days must be a number of days."

    if [[ $CHECK_HOMES == auto ]]; then
        if [[ -z $ROOT ]]; then CHECK_HOMES=1; else CHECK_HOMES=0; fi
    fi

    if [[ $CHECK_ACTIVITY == auto ]]; then
        if [[ -z $ROOT ]]; then CHECK_ACTIVITY=1; else CHECK_ACTIVITY=0; fi
    fi

    if [[ $USE_COLOR == auto ]]; then
        if [[ -t 1 && -z ${NO_COLOR:-} ]]; then USE_COLOR=1; else USE_COLOR=0; fi
    fi
}

# --------------------------------------------------------------------
# Loading: login.defs, passwd, shadow, group
# --------------------------------------------------------------------

load_login_defs() {
    local file line key value rest
    file=$(p etc/login.defs)

    [[ -r $file ]] || { warn_once "Cannot read /etc/login.defs; using default UID range and skipping policy checks."; return; }

    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        read -r key value rest <<< "$line"
        [[ -z $key || $key == \#* ]] && continue
        LOGIN_DEFS[$key]=${value//[[:cntrl:]]/?}
    done < "$file"

    if is_int "${LOGIN_DEFS[UID_MIN]:-}"; then UID_MIN=$(( 10#${LOGIN_DEFS[UID_MIN]} )); fi
    if is_int "${LOGIN_DEFS[UID_MAX]:-}"; then UID_MAX=$(( 10#${LOGIN_DEFS[UID_MAX]} )); fi
}

parse_passwd() {
    local file line lineno=0 colons name pw uid gid gecos home shell
    file=$(p etc/passwd)

    if [[ ! -r $file ]]; then
        ERRORS+=("Cannot read /etc/passwd")
        return 1
    fi

    while IFS= read -r line || [[ -n $line ]]; do
        lineno=$(( lineno + 1 ))
        line=${line%$'\r'}
        [[ -z ${line//[[:space:]]/} || $line == \#* ]] && continue

        colons=${line//[^:]/}

        if (( ${#colons} != 6 )); then
            add_finding MEDIUM UA-014 "passwd:$lineno" "Malformed entry in /etc/passwd" \
                "Line $lineno has $(( ${#colons} + 1 )) fields instead of 7." \
                "Fix the entry with vipw and validate the file with pwck."
            continue
        fi

        IFS=: read -r name pw uid gid gecos home shell <<< "$line"
        name=${name//[[:cntrl:]]/?}
        gecos=${gecos//[[:cntrl:]]/?}
        home=${home//[[:cntrl:]]/?}
        shell=${shell//[[:cntrl:]]/?}
        pw=${pw//[[:cntrl:]]/?}

        if ! valid_name "$name" || ! is_int "$uid" || ! is_int "$gid"; then
            add_finding MEDIUM UA-014 "passwd:$lineno" "Invalid entry in /etc/passwd" \
                "Line $lineno has an invalid user name, UID or GID." \
                "Fix the entry with vipw and validate the file with pwck."
            continue
        fi

        uid=$(( 10#$uid ))
        gid=$(( 10#$gid ))

        if [[ -n ${PW_UID[$name]+x} ]]; then
            add_finding HIGH UA-009 "$name" "Duplicate user name '$name'" \
                "The user name '$name' appears more than once in /etc/passwd (line $lineno); only the first entry is audited." \
                "Remove or rename the duplicate entry with vipw."
            continue
        fi

        USERS+=("$name")
        PW_PASS[$name]=$pw
        PW_UID[$name]=$uid
        PW_GID[$name]=$gid
        PW_GECOS[$name]=$gecos
        PW_HOME[$name]=$home
        PW_SHELL[$name]=$shell
        UID_OWNERS[$uid]+="$name "
        GID_PRIMARY_USERS[$gid]+="$name "
        [[ -z ${FIRST_USER_OF_UID[$uid]+x} ]] && FIRST_USER_OF_UID[$uid]=$name
    done < "$file"
}

parse_shadow() {
    local file line lineno=0 colons name hash lastchg max expire
    file=$(p etc/shadow)

    if [[ ! -r $file ]]; then
        warn_once "Cannot read /etc/shadow (run as root): password checks were skipped."
        return 1
    fi

    SHADOW_LOADED=1

    while IFS= read -r line || [[ -n $line ]]; do
        lineno=$(( lineno + 1 ))
        line=${line%$'\r'}
        [[ -z ${line//[[:space:]]/} || $line == \#* ]] && continue

        colons=${line//[^:]/}

        if (( ${#colons} != 8 )); then
            add_finding MEDIUM UA-014 "shadow:$lineno" "Malformed entry in /etc/shadow" \
                "Line $lineno has $(( ${#colons} + 1 )) fields instead of 9." \
                "Fix the entry with vipw -s and validate the file with pwck."
            continue
        fi

        IFS=: read -r name hash lastchg _ max _ _ expire _ <<< "$line"
        name=${name//[[:cntrl:]]/?}

        if ! valid_name "$name"; then
            add_finding MEDIUM UA-014 "shadow:$lineno" "Invalid entry in /etc/shadow" \
                "Line $lineno has an invalid user name." "Fix the entry with vipw -s."
            continue
        fi

        [[ -n ${SH_HASH[$name]+x} ]] && continue

        SH_HASH[$name]=${hash//[[:cntrl:]]/?}
        SH_LASTCHG[$name]=$lastchg
        SH_MAX[$name]=$max
        SH_EXPIRE[$name]=$expire
    done < "$file"
}

parse_group() {
    local file line lineno=0 colons name pw gid members
    file=$(p etc/group)

    if [[ ! -r $file ]]; then
        ERRORS+=("Cannot read /etc/group")
        return 1
    fi

    GROUP_LOADED=1

    while IFS= read -r line || [[ -n $line ]]; do
        lineno=$(( lineno + 1 ))
        line=${line%$'\r'}
        [[ -z ${line//[[:space:]]/} || $line == \#* ]] && continue

        colons=${line//[^:]/}

        if (( ${#colons} != 3 )); then
            add_finding MEDIUM UA-014 "group:$lineno" "Malformed entry in /etc/group" \
                "Line $lineno has $(( ${#colons} + 1 )) fields instead of 4." \
                "Fix the entry with vigr and validate the file with grpck."
            continue
        fi

        IFS=: read -r name pw gid members <<< "$line"
        name=${name//[[:cntrl:]]/?}
        members=${members//[[:cntrl:]]/?}

        if ! valid_name "$name" || ! is_int "$gid"; then
            add_finding MEDIUM UA-014 "group:$lineno" "Invalid entry in /etc/group" \
                "Line $lineno has an invalid group name or GID." "Fix the entry with vigr."
            continue
        fi

        gid=$(( 10#$gid ))

        if [[ -n ${GR_GID[$name]+x} ]]; then
            add_finding MEDIUM UA-011 "$name" "Duplicate group name '$name'" \
                "The group '$name' appears more than once in /etc/group (line $lineno); only the first entry is audited." \
                "Remove or rename the duplicate group with vigr."
            continue
        fi

        GROUP_NAMES+=("$name")
        GR_GID[$name]=$gid
        GR_MEMBERS[$name]=$members
        GID_OWNERS[$gid]+="$name "
        [[ -z ${FIRST_GROUP_OF_GID[$gid]+x} ]] && FIRST_GROUP_OF_GID[$gid]=$name
    done < "$file"
}

# Members of a group, including users whose primary group it is.
group_members() {
    local group=$1 member gid
    local -A seen=()
    local -a listed=()

    MEMBERS=()
    [[ -n ${GR_GID[$group]+x} ]] || return 0

    IFS=, read -ra listed <<< "${GR_MEMBERS[$group]}"

    for member in "${listed[@]}"; do
        [[ -z $member || -n ${seen[$member]+x} ]] && continue
        seen[$member]=1
        MEMBERS+=("$member")
    done

    gid=${GR_GID[$group]}

    for member in ${GID_PRIMARY_USERS[$gid]:-}; do
        [[ -n ${seen[$member]+x} ]] && continue
        seen[$member]=1
        MEMBERS+=("$member")
    done
}

# --------------------------------------------------------------------
# Account evaluation
# --------------------------------------------------------------------

# Classify a value of the password field. Sets H_STATE (empty|locked|hash),
# H_ALGO, H_WEAK (0 ok, 1 weak, 2 unrecognized) and H_RAW (the hash, if any).
hash_info() {
    local h=$1 body locked=0

    H_STATE="" H_ALGO="-" H_WEAK=0 H_RAW=""

    if [[ -z $h ]]; then
        H_STATE=empty
        return
    fi

    body=$h

    if [[ $h == '!'* || $h == '*'* ]]; then
        locked=1
    fi

    while [[ $body == '!'* || $body == '*'* ]]; do
        body=${body:1}
    done

    if [[ $body == '$'* || $body == _* || $body =~ ^[./0-9A-Za-z]{13}$ ]]; then
        H_RAW=$h

        case $body in
            '$1$'*) H_ALGO="md5crypt"; H_WEAK=1 ;;
            '$2a$'*|'$2b$'*|'$2x$'*|'$2y$'*) H_ALGO="bcrypt" ;;
            '$5$'*) H_ALGO="sha256crypt" ;;
            '$6$'*) H_ALGO="sha512crypt" ;;
            '$y$'*|'$gy$'*) H_ALGO="yescrypt" ;;
            '$7$'*) H_ALGO="scrypt" ;;
            '$sha1$'*) H_ALGO="sha1crypt"; H_WEAK=1 ;;
            '$md5$'*) H_ALGO="sunmd5"; H_WEAK=1 ;;
            _*) H_ALGO="bsdi-des"; H_WEAK=1 ;;
            '$'*) H_ALGO="unknown"; H_WEAK=2 ;;
            *) H_ALGO="des"; H_WEAK=1 ;;
        esac

        if (( locked )); then H_STATE="locked"; else H_STATE="hash"; fi
    else
        H_STATE=locked
    fi
}

shell_allows_login() {
    local shell=$1

    [[ -z $shell ]] && return 0

    case ${shell##*/} in
        nologin|false|true|sync|halt|shutdown) return 1 ;;
    esac

    return 0
}

evaluate_accounts() {
    local u pw uid

    for u in "${USERS[@]}"; do
        pw=${PW_PASS[$u]}
        uid=${PW_UID[$u]}

        if [[ $pw == x ]]; then
            if (( SHADOW_LOADED )); then
                if [[ -n ${SH_HASH[$u]+x} ]]; then
                    hash_info "${SH_HASH[$u]}"
                    ACC_SOURCE[$u]=shadow
                    ACC_STATE[$u]=$H_STATE
                else
                    H_ALGO="-" H_WEAK=0 H_RAW=""
                    ACC_SOURCE[$u]=none
                    ACC_STATE[$u]=missing
                fi
            else
                H_ALGO="-" H_WEAK=0 H_RAW=""
                ACC_SOURCE[$u]=none
                ACC_STATE[$u]=unknown
            fi
        else
            hash_info "$pw"
            ACC_SOURCE[$u]=passwd
            ACC_STATE[$u]=$H_STATE
        fi

        ACC_ALGO[$u]=$H_ALGO
        ACC_WEAK[$u]=$H_WEAK
        ACC_HASH[$u]=$H_RAW

        if (( uid == 0 )); then
            if [[ $u == root ]]; then ACC_TYPE[$u]=root; else ACC_TYPE[$u]=uid0; fi
        elif (( uid < UID_MIN )); then
            ACC_TYPE[$u]=system
        elif (( uid <= UID_MAX )); then
            ACC_TYPE[$u]=regular
        else
            ACC_TYPE[$u]=other
        fi

        if shell_allows_login "${PW_SHELL[$u]}"; then ACC_LOGIN[$u]=1; else ACC_LOGIN[$u]=0; fi
    done

    if (( GROUP_LOADED )); then
        local g m
        for g in "${GROUP_NAMES[@]}"; do
            group_members "$g"
            for m in "${MEMBERS[@]}"; do
                USER_GROUPS[$m]+="$g "
            done
        done
    fi
}

check_accounts() {
    local u uid gid state type login weak algo pw max lastchg age

    for u in "${USERS[@]}"; do
        uid=${PW_UID[$u]}
        gid=${PW_GID[$u]}
        state=${ACC_STATE[$u]}
        type=${ACC_TYPE[$u]}
        login=${ACC_LOGIN[$u]}
        weak=${ACC_WEAK[$u]}
        algo=${ACC_ALGO[$u]}
        pw=${PW_PASS[$u]}

        if (( uid == 0 )) && [[ $u != root ]]; then
            add_finding CRITICAL UA-001 "$u" "Account '$u' has UID 0 (root privileges)" \
                "Any account with UID 0 is equivalent to root. Only 'root' should have UID 0." \
                "Remove the account or give it a unique UID, and review how it was created."
        fi

        if [[ $state == empty ]]; then
            if (( login )); then
                add_finding CRITICAL UA-002 "$u" "Account '$u' has an empty password and a login shell" \
                    "The password field is empty (${ACC_SOURCE[$u]}), so the account may be used without a password." \
                    "Set a password with passwd or lock the account with passwd -l $u."
            else
                add_finding MEDIUM UA-002 "$u" "Account '$u' has an empty password" \
                    "The password field is empty (${ACC_SOURCE[$u]}). The shell does not allow login, but other services may accept the account." \
                    "Lock the account with passwd -l $u."
            fi
        fi

        if [[ ${ACC_SOURCE[$u]} == passwd && -n ${ACC_HASH[$u]} ]]; then
            add_finding HIGH UA-003 "$u" "Password hash stored in /etc/passwd for '$u'" \
                "Hashes in /etc/passwd are readable by every user, which allows offline cracking." \
                "Move the hash to /etc/shadow (run pwconv) and change the password."
        fi

        if (( weak == 1 )); then
            if [[ $state == locked ]]; then
                add_finding LOW UA-004 "$u" "Locked account '$u' uses a weak hash algorithm ($algo)" \
                    "The stored hash uses $algo, which is considered weak." \
                    "Change the password after unlocking so it is stored with SHA-512 or yescrypt."
            else
                add_finding MEDIUM UA-004 "$u" "Account '$u' uses a weak password hash ($algo)" \
                    "The stored hash uses $algo, which is considered weak and can be cracked quickly." \
                    "Change the password and set ENCRYPT_METHOD to SHA512 or YESCRYPT in /etc/login.defs."
            fi
        elif (( weak == 2 )); then
            add_finding MEDIUM UA-004 "$u" "Account '$u' has an unrecognized password hash format" \
                "The hash does not match a known crypt format." \
                "Verify the entry and reset the password if the format is not intended."
        fi

        if [[ $type == system ]] && (( login )); then
            add_finding MEDIUM UA-005 "$u" "System account '$u' has an interactive shell (${PW_SHELL[$u]:-/bin/sh})" \
                "System accounts (UID below $UID_MIN) should not allow interactive logins." \
                "Set the shell to /usr/sbin/nologin with usermod -s /usr/sbin/nologin $u."
        fi

        if [[ $state == missing ]]; then
            add_finding MEDIUM UA-006 "$u" "Account '$u' has no entry in /etc/shadow" \
                "/etc/passwd delegates the password to shadow, but there is no matching shadow entry." \
                "Run pwck to repair the files, then set or lock the password."
        fi

        if (( gid == 0 )) && [[ $u != root ]]; then
            add_finding MEDIUM UA-018 "$u" "Account '$u' has the root group as primary group" \
                "Members of GID 0 may get access to files owned by the root group." \
                "Assign a dedicated primary group with usermod -g."
        fi

        if (( GROUP_LOADED )) && [[ -z ${FIRST_GROUP_OF_GID[$gid]+x} ]]; then
            add_finding LOW UA-012 "$u" "Primary group of '$u' (GID $gid) does not exist" \
                "/etc/passwd references a GID that is not defined in /etc/group." \
                "Create the group or assign an existing one with usermod -g."
        fi

        if [[ $state == hash ]] && (( login )); then
            max=${SH_MAX[$u]:-}
            lastchg=${SH_LASTCHG[$u]:-}

            if [[ ${ACC_SOURCE[$u]} == shadow && ( $type == regular || $type == root ) ]]; then
                if [[ -z $max ]] || { is_int "$max" && (( 10#$max >= 99999 )); }; then
                    add_finding LOW UA-015 "$u" "Password of '$u' never expires" \
                        "The maximum password age is not set." \
                        "Set a maximum age with chage -M 365 $u."
                fi
            fi

            if is_int "$lastchg" && (( 10#$lastchg > 0 )); then
                age=$(( TODAY - 10#$lastchg ))

                if (( age > MAX_PASSWORD_AGE )); then
                    format_days "$lastchg"
                    add_finding LOW UA-016 "$u" "Password of '$u' has not changed for $age days" \
                        "The last change was on $FDAYS; the configured limit is $MAX_PASSWORD_AGE days." \
                        "Ask the user to change the password, or lock the account if it is unused."
                fi
            fi
        fi
    done

    local id owners count
    for id in "${!UID_OWNERS[@]}"; do
        owners=${UID_OWNERS[$id]% }
        set -- $owners
        count=$#
        if (( count > 1 )); then
            add_finding HIGH UA-008 "uid:$id" "UID $id is shared by several accounts" \
                "Accounts sharing UID $id: ${owners// /, }. They have identical file permissions." \
                "Give each account a unique UID and fix file ownership."
        fi
    done

    for id in "${!GID_OWNERS[@]}"; do
        owners=${GID_OWNERS[$id]% }
        set -- $owners
        count=$#
        if (( count > 1 )); then
            add_finding MEDIUM UA-010 "gid:$id" "GID $id is shared by several groups" \
                "Groups sharing GID $id: ${owners// /, }." \
                "Give each group a unique GID and fix file ownership."
        fi
    done

    if (( SHADOW_LOADED )); then
        for u in "${!SH_HASH[@]}"; do
            if [[ -z ${PW_UID[$u]+x} ]]; then
                add_finding LOW UA-007 "$u" "Shadow entry '$u' has no matching account" \
                    "/etc/shadow contains an entry for a user that is not in /etc/passwd." \
                    "Remove the stale entry with vipw -s or run pwck."
            fi
        done
    fi

    if (( GROUP_LOADED )); then
        local g m
        local -a listed
        for g in "${GROUP_NAMES[@]}"; do
            IFS=, read -ra listed <<< "${GR_MEMBERS[$g]}"
            for m in "${listed[@]}"; do
                [[ -z $m ]] && continue
                if [[ -z ${PW_UID[$m]+x} ]]; then
                    add_finding LOW UA-013 "$g" "Group '$g' lists unknown user '$m'" \
                        "The member '$m' of group '$g' has no account in /etc/passwd." \
                        "Remove the member with gpasswd -d $m $g."
                fi
            done
        done

        local members_text
        for g in "${ROOT_EQUIVALENT_GROUPS[@]}"; do
            group_members "$g"
            members_text=""
            for m in "${MEMBERS[@]}"; do
                [[ $m == root ]] && continue
                members_text+="${members_text:+, }$m"
            done
            if [[ -n $members_text ]]; then
                add_finding HIGH UA-025 "$g" "Members of group '$g' are effectively root" \
                    "Membership in '$g' allows privilege escalation to root. Members: $members_text." \
                    "Remove members that do not need it, or use sudo with specific commands instead."
            fi
        done
    fi
}

# --------------------------------------------------------------------
# sudoers
# --------------------------------------------------------------------

strip_comment() {
    # Remove trailing comments. "#" starts a comment unless it is followed
    # by a digit (user and group ids such as #1000 are valid in sudoers).
    local s=$1 out="" i c next prev
    local len=${#s}

    for (( i = 0; i < len; i++ )); do
        c=${s:i:1}

        if [[ $c == "#" ]]; then
            prev=""
            (( i > 0 )) && prev=${s:i-1:1}
            next=${s:i+1:1}

            if [[ -z $prev || $prev == [[:space:]] ]] && [[ ! $next =~ ^[0-9]$ ]]; then
                break
            fi
        fi

        out+=$c
    done

    REPLY=$out
}

expand_principals() {
    local list=$1 depth=$2 t g
    local -a tokens=()

    IFS=, read -ra tokens <<< "$list"

    for t in "${tokens[@]}"; do
        trim "$t"
        t=$REPLY

        [[ -z $t || $t == '!'* ]] && continue

        if [[ $t == ALL ]]; then
            EXP_ALL=1
        elif [[ $t == %* ]]; then
            g=${t#%}
            if [[ $g == '#'* ]]; then
                g=${g#\#}
                g=${FIRST_GROUP_OF_GID[$g]:-}
            fi
            [[ -n $g ]] && EXP_GROUPS+=("$g")
        elif [[ $t == '+'* ]]; then
            warn_once "Netgroups in sudoers (such as $t) are not expanded."
        elif [[ $t == '#'* ]]; then
            g=${t#\#}
            [[ -n ${FIRST_USER_OF_UID[$g]+x} ]] && EXP_USERS+=("${FIRST_USER_OF_UID[$g]}")
        elif [[ -n ${UALIAS[$t]+x} ]] && (( depth < 5 )); then
            expand_principals "${UALIAS[$t]}" $(( depth + 1 ))
        else
            EXP_USERS+=("$t")
        fi
    done
}

expand_commands() {
    local cmd=$1 depth=$2 item
    local -a items=()

    trim "$cmd"
    cmd=$REPLY

    [[ -z $cmd || $cmd == '!'* ]] && return

    if [[ -n ${CALIAS[$cmd]+x} ]] && (( depth < 5 )); then
        IFS=, read -ra items <<< "${CALIAS[$cmd]}"
        for item in "${items[@]}"; do
            expand_commands "$item" $(( depth + 1 ))
        done
    else
        CMD_LIST+=("$cmd")
    fi
}

sudoers_defaults() {
    local text=$1 src=$2

    if [[ $text == *'!authenticate'* ]]; then
        add_finding HIGH UA-024 "$src" "sudoers disables authentication (!authenticate)" \
            "A Defaults entry at $src lets sudo run without asking for a password." \
            "Remove '!authenticate' from the Defaults entry."
    fi

    if [[ $text == *'!env_reset'* ]]; then
        add_finding HIGH UA-024 "$src" "sudoers disables environment reset (!env_reset)" \
            "A Defaults entry at $src keeps the caller's environment, which enables privilege escalation." \
            "Remove '!env_reset' from the Defaults entry."
    fi

    if [[ $text =~ timestamp_timeout[[:space:]]*=[[:space:]]*-1 ]]; then
        add_finding MEDIUM UA-024 "$src" "sudo credentials never expire (timestamp_timeout=-1)" \
            "A Defaults entry at $src keeps sudo authentication cached indefinitely." \
            "Use a finite timestamp_timeout, for example 5."
    fi

    if [[ $text =~ env_keep ]] && [[ $text =~ LD_(PRELOAD|LIBRARY_PATH) ]]; then
        add_finding HIGH UA-024 "$src" "sudoers preserves dangerous environment variables" \
            "A Defaults entry at $src keeps LD_PRELOAD or LD_LIBRARY_PATH, which allows running code as root." \
            "Remove these variables from env_keep."
    fi

    if [[ $text =~ (^|[[:space:],])visiblepw([[:space:],]|$) ]]; then
        add_finding MEDIUM UA-024 "$src" "sudo allows visible password prompts (visiblepw)" \
            "A Defaults entry at $src lets sudo ask for a password without hiding it." \
            "Remove 'visiblepw' from the Defaults entry."
    fi
}

sudoers_rule() {
    local s=$1 src=$2 lhs rhs hosts principals runas="" runas_users runas_root=1
    local nopass=0 element tag rest
    local -a elements=()

    [[ $s == *=* ]] || return

    lhs=${s%%=*}
    rhs=${s#*=}
    trim "$lhs"; lhs=$REPLY
    trim "$rhs"; rhs=$REPLY

    [[ $lhs == *[[:space:]]* ]] || return

    hosts=${lhs##*[[:space:]]}
    principals=${lhs%[[:space:]]*}
    trim "$principals"; principals=$REPLY

    [[ -n $principals && -n $hosts ]] || return

    if [[ $rhs == '('* ]]; then
        runas=${rhs%%)*}
        runas=${runas#(}
        rhs=${rhs#*)}
        trim "$rhs"; rhs=$REPLY

        runas_users=${runas%%:*}
        runas_root=0

        if [[ -z $runas_users ]]; then
            runas_root=1
        else
            local -a ru=()
            local r
            IFS=, read -ra ru <<< "$runas_users"
            for r in "${ru[@]}"; do
                trim "$r"
                [[ $REPLY == ALL || $REPLY == root ]] && runas_root=1
            done
        fi
    fi

    IFS=, read -ra elements <<< "$rhs"

    for element in "${elements[@]}"; do
        trim "$element"
        element=$REPLY

        while [[ $element =~ ^([A-Z_]+):[[:space:]]*(.*)$ ]]; do
            tag=${BASH_REMATCH[1]}
            rest=${BASH_REMATCH[2]}

            case $tag in
                NOPASSWD) nopass=1 ;;
                PASSWD) nopass=0 ;;
            esac

            element=$rest
        done

        [[ -z $element ]] && continue

        R_PRINC+=("$principals")
        R_RUNAS_ROOT+=("$runas_root")
        R_NOPASS+=("$nopass")
        R_CMD+=("$element")
        R_SRC+=("$src")
    done
}

sudoers_alias() {
    local kind=$1 body=$2 segment name list
    local -a segments=()

    IFS=: read -ra segments <<< "$body"

    for segment in "${segments[@]}"; do
        [[ $segment == *=* ]] || continue

        name=${segment%%=*}
        list=${segment#*=}
        trim "$name"; name=$REPLY
        trim "$list"; list=$REPLY

        [[ -n $name ]] || continue

        case $kind in
            User_Alias) UALIAS[$name]=$list ;;
            Cmnd_Alias|Cmd_Alias) CALIAS[$name]=$list ;;
        esac
    done
}

parse_sudoers_file() {
    local file=$1 depth=$2 line cont="" lineno=0 s name base entry

    (( depth > 10 )) && { warn_once "sudoers includes are nested too deeply; some files were skipped."; return; }
    [[ -n ${SEEN_FILES[$file]+x} ]] && return
    SEEN_FILES[$file]=1

    if [[ ! -r $file ]]; then
        warn_once "Cannot read ${file#"$ROOT"} (run as root): sudo privileges may be incomplete."
        return
    fi

    while IFS= read -r line || [[ -n $line ]]; do
        lineno=$(( lineno + 1 ))
        line=${line%$'\r'}

        if [[ $line == *\\ ]]; then
            cont+="${line%\\} "
            continue
        fi

        line="$cont$line"
        cont=""

        trim "$line"
        s=$REPLY
        [[ -z $s ]] && continue

        if [[ $s =~ ^(#includedir|@includedir)[[:space:]]+(.+)$ ]]; then
            name=${BASH_REMATCH[2]//\"/}
            [[ -d $(p "$name") ]] || continue
            for entry in "$(p "$name")"/*; do
                [[ -f $entry ]] || continue
                base=${entry##*/}
                [[ $base == *~ || $base == *.* ]] && continue
                parse_sudoers_file "$entry" $(( depth + 1 ))
            done
            continue
        fi

        if [[ $s =~ ^(#include|@include)[[:space:]]+(.+)$ ]]; then
            name=${BASH_REMATCH[2]//\"/}
            parse_sudoers_file "$(p "$name")" $(( depth + 1 ))
            continue
        fi

        strip_comment "$s"
        trim "$REPLY"
        s=$REPLY
        [[ -z $s ]] && continue

        case $s in
            Defaults*) sudoers_defaults "$s" "${file#"$ROOT"}:$lineno" ;;
            User_Alias[[:space:]]*|Cmnd_Alias[[:space:]]*|Cmd_Alias[[:space:]]*|Host_Alias[[:space:]]*|Runas_Alias[[:space:]]*)
                sudoers_alias "${s%%[[:space:]]*}" "${s#*[[:space:]]}" ;;
            *) sudoers_rule "$s" "${file#"$ROOT"}:$lineno" ;;
        esac
    done < "$file"
}

set_sudo_level() {
    # user level(1 limited, 2 full)
    local current=${SUDO_LEVEL[$1]:-0}
    (( $2 > current )) && SUDO_LEVEL[$1]=$2
}

analyze_sudo_rules() {
    local i princ cmd src nopass is_all level c first base wildcard dangerous u g m
    local -a affected

    for (( i = 0; i < ${#R_CMD[@]}; i++ )); do
        (( ${R_RUNAS_ROOT[i]} )) || continue

        princ=${R_PRINC[i]}
        cmd=${R_CMD[i]}
        src=${R_SRC[i]}
        nopass=${R_NOPASS[i]}

        EXP_ALL=0 EXP_USERS=() EXP_GROUPS=()
        expand_principals "$princ" 0

        CMD_LIST=()
        expand_commands "$cmd" 0

        is_all=0 wildcard=0 dangerous=""

        for c in "${CMD_LIST[@]}"; do
            if [[ $c == ALL ]]; then
                is_all=1
                continue
            fi

            first=${c%%[[:space:]]*}
            base=${first##*/}

            if [[ $DANGEROUS_COMMANDS == *" $base "* && ", $dangerous, " != *", $base, "* ]]; then
                dangerous+="${dangerous:+, }$base"
            fi

            [[ $c == *'*'* ]] && wildcard=1
        done

        if (( is_all )); then level=2; else level=1; fi

        affected=()

        for u in "${EXP_USERS[@]}"; do
            affected+=("$u")
        done

        for g in "${EXP_GROUPS[@]}"; do
            group_members "$g"
            for m in "${MEMBERS[@]}"; do
                affected+=("$m")
            done
        done

        for u in "${affected[@]}"; do
            set_sudo_level "$u" "$level"
        done

        if (( EXP_ALL )); then
            (( level > SUDO_EVERYONE )) && SUDO_EVERYONE=$level

            if (( is_all )); then
                add_finding CRITICAL UA-021 "$src" "sudoers lets every user run any command as root" \
                    "The rule at $src grants ALL commands to ALL users (principal: $princ)." \
                    "Restrict the rule to specific users or groups."
            fi
        fi

        if (( nopass )); then
            if (( is_all )); then
                add_finding HIGH UA-020 "$src" "Passwordless sudo for ALL commands ($princ)" \
                    "The rule at $src lets '$princ' run any command as root without a password." \
                    "Remove NOPASSWD, or restrict the rule to the specific commands that need it."
            else
                add_finding MEDIUM UA-020 "$src" "Passwordless sudo rule for $princ" \
                    "The rule at $src lets '$princ' run '$cmd' as root without a password." \
                    "Require a password unless the command is strictly needed for automation."
            fi
        fi

        if [[ -n $dangerous ]]; then
            if (( nopass )); then
                add_finding HIGH UA-022 "$src" "sudo rule allows '$dangerous', which can spawn a root shell (no password)" \
                    "The rule at $src lets '$princ' run '$dangerous' as root without a password. Shells, editors, pagers and interpreters can be used to escape to a root shell." \
                    "Allow a wrapper script or a more specific command, or use sudoedit for file editing."
            else
                add_finding MEDIUM UA-022 "$src" "sudo rule allows '$dangerous', which can spawn a root shell" \
                    "The rule at $src lets '$princ' run '$dangerous' as root. Shells, editors, pagers and interpreters can be used to escape to a root shell." \
                    "Allow a wrapper script or a more specific command, or use sudoedit for file editing."
            fi
        fi

        if (( wildcard )); then
            add_finding MEDIUM UA-023 "$src" "sudo rule uses a wildcard in the command" \
                "The rule at $src allows '$cmd' for '$princ'. Wildcards in sudo commands often allow extra arguments or path tricks." \
                "Replace wildcards with explicit arguments."
        fi
    done
}

load_sudoers() {
    local file
    file=$(p etc/sudoers)

    if [[ ! -e $file ]]; then
        warn_once "/etc/sudoers not found: sudo privileges were not audited."
        return
    fi

    if [[ ! -r $file ]]; then
        warn_once "Cannot read /etc/sudoers (run as root): sudo privileges were estimated from group names."
        return
    fi

    SUDOERS_LOADED=1
    parse_sudoers_file "$file" 0
    analyze_sudo_rules
}

fallback_sudo_groups() {
    # Used only when sudoers cannot be read.
    local g m

    for g in sudo wheel admin; do
        group_members "$g"
        for m in "${MEMBERS[@]}"; do
            set_sudo_level "$m" 2
        done
    done
}

# --------------------------------------------------------------------
# SSH daemon and password policy
# --------------------------------------------------------------------

parse_sshd_file() {
    local file=$1 depth=$2 line s kw val pattern entry
    local -a matches=()

    (( depth > 5 )) && return
    [[ -r $file ]] || return

    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%$'\r'}
        trim "$line"
        s=$REPLY
        [[ -z $s || $s == \#* ]] && continue

        [[ $s =~ ^([A-Za-z]+)[[:space:]=]+(.*)$ ]] || continue

        kw=${BASH_REMATCH[1],,}
        val=${BASH_REMATCH[2]}
        val=${val//\"/}

        case $kw in
            match) break ;;
            include)
                for pattern in $val; do
                    [[ $pattern == /* ]] || pattern="/etc/ssh/$pattern"
                    mapfile -t matches < <(cd "${ROOT:-/}" 2>/dev/null && compgen -G "${pattern#/}" | sort)
                    for entry in "${matches[@]}"; do
                        parse_sshd_file "$(p "$entry")" $(( depth + 1 ))
                    done
                done
                ;;
            *)
                if [[ -z ${SSHD[$kw]+x} ]]; then
                    val=${val%%[[:space:]]*}
                    SSHD[$kw]=${val,,}
                fi
                ;;
        esac
    done < "$file"
}

check_sshd() {
    local file value
    file=$(p etc/ssh/sshd_config)

    if [[ ! -r $file ]]; then
        warn_once "sshd_config not found or unreadable: SSH checks were skipped."
        return
    fi

    parse_sshd_file "$file" 0

    value=${SSHD[permitrootlogin]:-prohibit-password}

    if [[ $value == yes ]]; then
        add_finding HIGH UA-040 "sshd_config" "SSH allows root login with a password (PermitRootLogin yes)" \
            "Remote root login with a password exposes the most privileged account to brute force attacks." \
            "Set PermitRootLogin to prohibit-password or no."
    fi

    value=${SSHD[permitemptypasswords]:-no}

    if [[ $value == yes ]]; then
        add_finding CRITICAL UA-041 "sshd_config" "SSH accepts empty passwords (PermitEmptyPasswords yes)" \
            "Accounts without a password can log in remotely." \
            "Set PermitEmptyPasswords to no."
    fi

    value=${SSHD[passwordauthentication]:-yes}

    if [[ $value == yes ]]; then
        add_finding LOW UA-042 "sshd_config" "SSH allows password authentication" \
            "Password logins are exposed to brute force and credential stuffing." \
            "Use key-based authentication and set PasswordAuthentication to no."
    fi
}

check_login_defs() {
    local value method

    [[ ${#LOGIN_DEFS[@]} -gt 0 ]] || return

    value=${LOGIN_DEFS[PASS_MAX_DAYS]:-}

    if is_int "$value" && (( 10#$value > 365 )); then
        add_finding LOW UA-050 "login.defs" "Default maximum password age is $value days" \
            "PASS_MAX_DAYS in /etc/login.defs applies to new accounts." \
            "Set PASS_MAX_DAYS to 365 or less."
    fi

    method=${LOGIN_DEFS[ENCRYPT_METHOD]:-}

    case ${method^^} in
        DES|MD5)
            add_finding MEDIUM UA-051 "login.defs" "Default password hash algorithm is ${method^^}" \
                "ENCRYPT_METHOD in /etc/login.defs selects a weak algorithm for new passwords." \
                "Set ENCRYPT_METHOD to SHA512 or YESCRYPT."
            ;;
    esac
}

# --------------------------------------------------------------------
# File permissions
# --------------------------------------------------------------------

perm_check() {
    # relative-path label kind(open|secret|policy)
    local rel=$1 label=$2 kind=$3 file mode owner m

    file=$(p "$rel")
    [[ -e $file ]] || return 0

    if ! read -r mode owner < <(stat -L -c '%a %u' -- "$file" 2>/dev/null); then
        warn_once "Cannot read the permissions of $label."
        return 0
    fi

    m=$(( 8#$mode ))

    if (( owner != 0 )); then
        add_finding HIGH UA-030 "$label" "$label is not owned by root (owner UID $owner)" \
            "A non-root owner can change this file." \
            "Run chown root $label."
    fi

    if (( m & 8#002 )); then
        add_finding CRITICAL UA-030 "$label" "$label is writable by everyone (mode $mode)" \
            "Any user can modify this file." \
            "Run chmod o-w $label."
    elif (( m & 8#020 )); then
        add_finding HIGH UA-030 "$label" "$label is writable by its group (mode $mode)" \
            "Members of the file's group can modify it." \
            "Run chmod g-w $label."
    fi

    case $kind in
        secret)
            if (( m & 8#007 )); then
                add_finding CRITICAL UA-030 "$label" "$label is accessible by other users (mode $mode)" \
                    "This file contains password hashes and must not be accessible to ordinary users." \
                    "Run chmod 640 $label (or 600)."
            fi
            ;;
        policy)
            if (( m & 8#004 )); then
                add_finding LOW UA-030 "$label" "$label is readable by other users (mode $mode)" \
                    "The privilege policy is visible to every user." \
                    "Run chmod 440 $label."
            fi
            ;;
    esac
}

check_permissions() {
    local entry dir mode m

    perm_check etc/passwd /etc/passwd open
    perm_check etc/group /etc/group open
    perm_check etc/shadow /etc/shadow secret
    perm_check etc/gshadow /etc/gshadow secret
    perm_check etc/sudoers /etc/sudoers policy
    perm_check etc/ssh/sshd_config /etc/ssh/sshd_config open

    dir=$(p etc/sudoers.d)

    if [[ -d $dir ]]; then
        if mode=$(stat -L -c '%a' -- "$dir" 2>/dev/null); then
            m=$(( 8#$mode ))

            if (( m & 8#022 )); then
                add_finding CRITICAL UA-030 "/etc/sudoers.d" "/etc/sudoers.d is writable by group or others (mode $mode)" \
                    "Anyone who can write here can grant themselves root through sudo." \
                    "Run chmod 750 /etc/sudoers.d."
            fi
        fi

        for entry in "$dir"/*; do
            [[ -f $entry ]] || continue
            perm_check "etc/sudoers.d/${entry##*/}" "/etc/sudoers.d/${entry##*/}" policy
        done
    fi
}

# --------------------------------------------------------------------
# Home directories (live systems or --check-homes)
# --------------------------------------------------------------------

check_homes() {
    local u home dir mode owner m ssh_dir keys file count

    HOMES_CHECKED=1

    for u in "${USERS[@]}"; do
        (( ${ACC_LOGIN[$u]} )) || continue

        home=${PW_HOME[$u]}
        [[ $home == /* && $home != / ]] || continue

        dir=$(p "$home")

        if [[ ! -d $dir ]]; then
            if [[ ${ACC_STATE[$u]} == hash ]]; then
                add_finding LOW UA-060 "$u" "Home directory of '$u' does not exist ($home)" \
                    "The account can log in with a password but its home directory is missing." \
                    "Create the directory or disable the account."
            fi
            continue
        fi

        if read -r mode owner < <(stat -L -c '%a %u' -- "$dir" 2>/dev/null); then
            m=$(( 8#$mode ))

            if (( m & 8#002 )); then
                add_finding HIGH UA-061 "$u" "Home directory of '$u' is writable by everyone (mode $mode)" \
                    "Any user can plant files such as shell startup scripts in $home." \
                    "Run chmod 750 $home."
            elif (( m & 8#020 )); then
                add_finding MEDIUM UA-061 "$u" "Home directory of '$u' is writable by its group (mode $mode)" \
                    "Group members can modify files in $home." \
                    "Run chmod 750 $home."
            fi

            if (( owner != ${PW_UID[$u]} )); then
                add_finding MEDIUM UA-062 "$u" "Home directory of '$u' is owned by UID $owner" \
                    "The owner of $home is not the account that uses it." \
                    "Run chown ${PW_UID[$u]} $home."
            fi
        fi

        ssh_dir="$dir/.ssh"

        if [[ -d $ssh_dir ]]; then
            if mode=$(stat -L -c '%a' -- "$ssh_dir" 2>/dev/null) && (( 8#$mode & 8#077 )); then
                add_finding MEDIUM UA-063 "$u" "The .ssh directory of '$u' is accessible by others (mode $mode)" \
                    "SSH may refuse keys and other users can read private material." \
                    "Run chmod 700 $home/.ssh."
            fi

            for keys in authorized_keys authorized_keys2; do
                file="$ssh_dir/$keys"
                [[ -f $file ]] || continue

                if mode=$(stat -L -c '%a' -- "$file" 2>/dev/null) && (( 8#$mode & 8#022 )); then
                    add_finding HIGH UA-063 "$u" "$keys of '$u' is writable by others (mode $mode)" \
                        "Another user could add a key and log in as '$u'." \
                        "Run chmod 600 $home/.ssh/$keys."
                fi

                count=$(grep -cvE '^[[:space:]]*(#|$)' "$file" 2>/dev/null) || count=0
                KEY_COUNT[$u]=$(( ${KEY_COUNT[$u]:-0} + count ))
            done
        fi

        if [[ -e $dir/.rhosts ]]; then
            add_finding HIGH UA-064 "$u" "'$u' has a .rhosts file" \
                "The file enables legacy host-based trust (rlogin/rsh) and can allow logins without a password." \
                "Remove $home/.rhosts."
        fi

        if [[ -f $dir/.netrc ]] && mode=$(stat -L -c '%a' -- "$dir/.netrc" 2>/dev/null) && (( 8#$mode & 8#077 )); then
            add_finding MEDIUM UA-064 "$u" "'$u' has a .netrc file readable by others (mode $mode)" \
                "The file may contain plaintext credentials." \
                "Run chmod 600 $home/.netrc or remove it."
        fi
    done
}

# --------------------------------------------------------------------
# Login activity (lastlog)
# --------------------------------------------------------------------

check_activity() {
    local line user stamp epoch days

    if ! command -v lastlog >/dev/null 2>&1; then
        warn_once "lastlog is not available: login activity checks were skipped."
        return
    fi

    ACTIVITY_CHECKED=1

    while IFS= read -r line; do
        [[ $line == Username* ]] && continue

        user=${line%% *}
        [[ -n ${PW_UID[$user]+x} ]] || continue
        [[ ${ACC_TYPE[$user]} == root ]] && continue

        # Only accounts that can log in with a usable password matter.
        [[ ${ACC_STATE[$user]} == hash ]] || continue
        (( ${ACC_LOGIN[$user]} )) || continue

        if [[ $line == *'**Never logged in**'* ]]; then
            add_finding LOW UA-071 "$user" "Account '$user' has never logged in" \
                "The account has a password and a login shell but no login is recorded." \
                "Lock or remove the account if it is not needed."
            continue
        fi

        if [[ $line =~ ([A-Z][a-z]{2}\ [A-Z][a-z]{2}\ +[0-9]+\ [0-9]{2}:[0-9]{2}:[0-9]{2}\ ([+-][0-9]{4}\ )?[0-9]{4})$ ]]; then
            stamp=${BASH_REMATCH[1]}
            epoch=$(date -d "$stamp" +%s 2>/dev/null) || continue
            days=$(( (NOW - epoch) / 86400 ))

            if (( days > INACTIVE_DAYS )); then
                add_finding LOW UA-070 "$user" "Account '$user' has been inactive for $days days" \
                    "The last login was $days days ago (threshold: $INACTIVE_DAYS days)." \
                    "Lock the account with passwd -l $user, or remove it if it is no longer needed."
            fi
        fi
    done < <(lastlog 2>/dev/null)
}

# --------------------------------------------------------------------
# Report
# --------------------------------------------------------------------

# Effective sudo level: own rules, plus "ALL" principals for accounts
# that can log in.
sudo_level_of() {
    # result in SLEVEL
    SLEVEL=${SUDO_LEVEL[$1]:-0}

    if (( SUDO_EVERYONE > SLEVEL )) && (( ${ACC_LOGIN[$1]:-0} )); then
        SLEVEL=$SUDO_EVERYONE
    fi
}

sudo_label() {
    # result in SLABEL
    sudo_level_of "$1"

    case $SLEVEL in
        2) SLABEL=full ;;
        1) SLABEL=limited ;;
        *) SLABEL=- ;;
    esac
}

account_status_label() {
    # result in STLABEL
    case ${ACC_STATE[$1]} in
        hash) STLABEL=password ;;
        locked) STLABEL=locked ;;
        empty) STLABEL=NO-PASSWORD ;;
        missing) STLABEL=no-shadow ;;
        *) STLABEL=unknown ;;
    esac
}

account_visible() {
    local u=$1

    (( ALL_ACCOUNTS )) && return 0
    [[ ${ACC_TYPE[$u]} == regular || ${ACC_TYPE[$u]} == root || ${ACC_TYPE[$u]} == uid0 ]] && return 0
    (( ${ACC_LOGIN[$u]} )) && return 0
    sudo_level_of "$u"
    (( SLEVEL > 0 )) && return 0

    return 1
}

declare -A SEV_COUNT=()

count_all_findings() {
    local sev
    SEV_COUNT=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0)

    for sev in "${F_SEV[@]}"; do
        SEV_COUNT[$sev]=$(( ${SEV_COUNT[$sev]} + 1 ))
    done
}

names_with_level() {
    local level=$1 u out=""

    for u in "${USERS[@]}"; do
        sudo_level_of "$u"
        (( SLEVEL == level )) && out+="${out:+, }$u"
    done

    printf '%s' "$out"
}

print_report() {
    local u i sev min shown=0 total_regular=0 total_system=0 total_login=0 total_locked=0 total_empty=0
    local sudo_full sudo_limited shell changed expires notes keys
    local c_err="" c_warn="" c_off="" c_on=""

    if (( USE_COLOR )); then
        c_err=$'\033[1;31m' c_warn=$'\033[33m' c_off=$'\033[0m'
    fi

    for u in "${USERS[@]}"; do
        case ${ACC_TYPE[$u]} in
            regular) total_regular=$(( total_regular + 1 )) ;;
            *) total_system=$(( total_system + 1 )) ;;
        esac
        (( ${ACC_LOGIN[$u]} )) && total_login=$(( total_login + 1 ))
        [[ ${ACC_STATE[$u]} == locked ]] && total_locked=$(( total_locked + 1 ))
        [[ ${ACC_STATE[$u]} == empty ]] && total_empty=$(( total_empty + 1 ))
    done

    printf 'Linux User Auditor %s\n' "$VERSION"
    printf 'Root: %s | Host: %s | Date: %s | Running as UID %s\n' "${ROOT:-/}" "$HOST_NAME" "$STARTED_AT" "$EUID"
    printf 'UID ranges: system < %s, regular %s-%s\n' "$UID_MIN" "$UID_MIN" "$UID_MAX"

    for i in "${!ERRORS[@]}"; do
        printf '%s[ERROR]%s %s\n' "$c_err" "$c_off" "${ERRORS[i]}"
    done

    for i in "${!WARNINGS[@]}"; do
        printf '%s[WARNING]%s %s\n' "$c_warn" "$c_off" "${WARNINGS[i]}"
    done

    printf '\nInventory\n'
    printf '  Accounts: %s total | %s regular | %s system/other | %s with login shell | %s locked | %s without password\n' \
        "${#USERS[@]}" "$total_regular" "$total_system" "$total_login" "$total_locked" "$total_empty"

    sudo_full=$(names_with_level 2)
    sudo_limited=$(names_with_level 1)

    if (( SUDOERS_LOADED )); then
        printf '  sudo (full access as root): %s\n' "${sudo_full:--}"
        printf '  sudo (limited commands):    %s\n' "${sudo_limited:--}"
        (( SUDO_EVERYONE > 0 )) && printf '  sudo granted to ALL users (level: %s)\n' "$( (( SUDO_EVERYONE == 2 )) && printf full || printf limited )"
    else
        printf '  sudo (estimated from groups sudo/wheel/admin): %s\n' "${sudo_full:--}"
    fi

    if [[ -n ${SSHD[permitrootlogin]+x} || -n ${SSHD[passwordauthentication]+x} || ${#SSHD[@]} -gt 0 ]]; then
        printf '  SSH: PermitRootLogin=%s PasswordAuthentication=%s PermitEmptyPasswords=%s\n' \
            "${SSHD[permitrootlogin]:-prohibit-password(default)}" \
            "${SSHD[passwordauthentication]:-yes(default)}" \
            "${SSHD[permitemptypasswords]:-no(default)}"
    fi

    printf '\nAccounts'
    (( ALL_ACCOUNTS )) || printf ' (regular, login-capable and privileged; use --all-accounts for all)'
    printf '\n'
    printf '  %-18s %-6s %-6s %-14s %-12s %-11s %-11s %-8s %s\n' USER UID GID SHELL STATUS CHANGED EXPIRES SUDO NOTES

    for u in "${USERS[@]}"; do
        account_visible "$u" || continue
        shown=$(( shown + 1 ))

        shell=${PW_SHELL[$u]##*/}
        [[ -z $shell ]] && shell="sh"

        changed="-"
        if [[ -n ${SH_LASTCHG[$u]+x} ]]; then
            case ${SH_LASTCHG[$u]} in
                0) changed="must-change" ;;
                *) format_days "${SH_LASTCHG[$u]}"; changed=$FDAYS ;;
            esac
        fi

        format_days "${SH_EXPIRE[$u]:-}"
        expires=$FDAYS

        notes=""
        [[ ${ACC_TYPE[$u]} == uid0 ]] && notes+="uid0 "
        [[ ${ACC_TYPE[$u]} == system ]] && notes+="system "
        (( ${ACC_LOGIN[$u]} )) || notes+="no-login "
        [[ -n ${KEY_COUNT[$u]+x} ]] && notes+="keys:${KEY_COUNT[$u]} "
        [[ ${ACC_WEAK[$u]} == 1 ]] && notes+="weak-hash(${ACC_ALGO[$u]}) "

        account_status_label "$u"
        sudo_label "$u"

        printf '  %-18.18s %-6s %-6s %-14.14s %-12s %-11s %-11s %-8s %s\n' \
            "$u" "${PW_UID[$u]}" "${PW_GID[$u]}" "$shell" "$STLABEL" \
            "$changed" "$expires" "$SLABEL" "${notes% }"
    done

    (( shown == 0 )) && printf '  (none)\n'

    sevn "$MIN_SEVERITY"
    min=$SEVN

    printf '\nFindings (minimum severity: %s)\n' "$MIN_SEVERITY"

    local count=0

    for sev in CRITICAL HIGH MEDIUM LOW; do
        (( ${SEV_NUM[$sev]} >= min )) || continue

        c_on=""
        if (( USE_COLOR )); then
            case $sev in
                CRITICAL) c_on=$'\033[1;31m' ;;
                HIGH) c_on=$'\033[31m' ;;
                MEDIUM) c_on=$'\033[33m' ;;
                LOW) c_on=$'\033[36m' ;;
            esac
        fi

        for (( i = 0; i < ${#F_SEV[@]}; i++ )); do
            [[ ${F_SEV[i]} == "$sev" ]] || continue
            count=$(( count + 1 ))

            printf '%s[%s]%s %s %s\n' "$c_on" "$sev" "$c_off" "${F_ID[i]}" "${F_TITLE[i]}"
            printf '    %s\n' "${F_DETAIL[i]}"
            printf '    Fix: %s\n' "${F_REC[i]}"
        done
    done

    (( count == 0 )) && printf '  No findings.\n'

    if (( SHOW_HASHES )); then
        printf '\nPassword hashes (SENSITIVE - do not share or store this output)\n'
        printf '  %-18s %-8s %-12s %s\n' USER SOURCE ALGORITHM HASH

        local any=0

        for u in "${USERS[@]}"; do
            [[ -n ${ACC_HASH[$u]} ]] || continue
            any=1
            printf '  %-18.18s %-8s %-12s %s\n' "$u" "${ACC_SOURCE[$u]}" "${ACC_ALGO[$u]}" "${ACC_HASH[$u]}"
        done

        (( any )) || printf '  (no hashes found)\n'
    fi

    printf '\nSummary: %s CRITICAL | %s HIGH | %s MEDIUM | %s LOW' \
        "${SEV_COUNT[CRITICAL]}" "${SEV_COUNT[HIGH]}" "${SEV_COUNT[MEDIUM]}" "${SEV_COUNT[LOW]}"
    printf ' (%s findings in total)\n' "${#F_SEV[@]}"

    if (( ! CHECK_PERMISSIONS )); then printf 'Note: file permission checks were skipped.\n'; fi
    if (( ! HOMES_CHECKED )); then printf 'Note: home directory checks were skipped (use --check-homes).\n'; fi
    if (( ! ACTIVITY_CHECKED )); then printf 'Note: login activity checks were skipped (use --check-activity on a live system).\n'; fi
}

# --------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------

jstr() {
    local s=$1
    s=${s//[[:cntrl:]]/?}
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    J+="\"$s\""
}

jkey() {
    J+="\"$1\":"
}

jnum_or_null() {
    if is_int "$1"; then J+="$1"; else J+="null"; fi
}

jbool() {
    if (( $1 )); then J+="true"; else J+="false"; fi
}

jarray_words() {
    local first=1 w
    J+="["
    for w in $1; do
        (( first )) || J+=","
        first=0
        jstr "$w"
    done
    J+="]"
}

flush_json() {
    printf '%s' "$J" >&3
    J=""
}

build_json() {
    local u i sev first=1 min
    sevn "$MIN_SEVERITY"; min=$SEVN

    J="{"
    jkey tool; jstr "linux-user-auditor"
    J+=","; jkey version; jstr "$VERSION"
    J+=","; jkey generated_at; jstr "$STARTED_AT"
    J+=","; jkey root; jstr "${ROOT:-/}"
    J+=","; jkey host; jstr "$HOST_NAME"
    J+=","; jkey uid_min; J+="$UID_MIN"
    J+=","; jkey uid_max; J+="$UID_MAX"
    J+=","; jkey hashes_included; jbool "$SHOW_HASHES"

    J+=","; jkey summary; J+="{"
    jkey accounts; J+="${#USERS[@]}"
    J+=","; jkey findings; J+="${#F_SEV[@]}"
    J+=","; jkey critical; J+="${SEV_COUNT[CRITICAL]}"
    J+=","; jkey high; J+="${SEV_COUNT[HIGH]}"
    J+=","; jkey medium; J+="${SEV_COUNT[MEDIUM]}"
    J+=","; jkey low; J+="${SEV_COUNT[LOW]}"
    J+="}"

    J+=","; jkey accounts; J+="["
    first=1
    for u in "${USERS[@]}"; do
        (( first )) || J+=","
        first=0
        J+="{"
        jkey user; jstr "$u"
        J+=","; jkey uid; J+="${PW_UID[$u]}"
        J+=","; jkey gid; J+="${PW_GID[$u]}"
        J+=","; jkey gecos; jstr "${PW_GECOS[$u]}"
        J+=","; jkey home; jstr "${PW_HOME[$u]}"
        J+=","; jkey shell; jstr "${PW_SHELL[$u]}"
        J+=","; jkey type; jstr "${ACC_TYPE[$u]}"
        J+=","; jkey login_shell; jbool "${ACC_LOGIN[$u]}"
        J+=","; jkey password_state; jstr "${ACC_STATE[$u]}"
        J+=","; jkey password_source; jstr "${ACC_SOURCE[$u]}"
        J+=","; jkey hash_algorithm; jstr "${ACC_ALGO[$u]}"
        if (( SHOW_HASHES )); then
            J+=","; jkey hash
            if [[ -n ${ACC_HASH[$u]} ]]; then jstr "${ACC_HASH[$u]}"; else J+="null"; fi
        fi
        J+=","; jkey password_last_changed_days; jnum_or_null "${SH_LASTCHG[$u]:-}"
        J+=","; jkey password_max_days; jnum_or_null "${SH_MAX[$u]:-}"
        J+=","; jkey account_expires_days; jnum_or_null "${SH_EXPIRE[$u]:-}"
        sudo_label "$u"
        J+=","; jkey sudo; jstr "$SLABEL"
        J+=","; jkey groups; jarray_words "${USER_GROUPS[$u]:-}"
        J+=","; jkey authorized_keys; jnum_or_null "${KEY_COUNT[$u]:-}"
        J+="}"
        flush_json
    done
    J+="]"

    J+=","; jkey findings; J+="["
    first=1
    for sev in CRITICAL HIGH MEDIUM LOW; do
        (( ${SEV_NUM[$sev]} >= min )) || continue
        for (( i = 0; i < ${#F_SEV[@]}; i++ )); do
            [[ ${F_SEV[i]} == "$sev" ]] || continue
            (( first )) || J+=","
            first=0
            J+="{"
            jkey id; jstr "${F_ID[i]}"
            J+=","; jkey severity; jstr "${F_SEV[i]}"
            J+=","; jkey subject; jstr "${F_SUBJECT[i]}"
            J+=","; jkey title; jstr "${F_TITLE[i]}"
            J+=","; jkey detail; jstr "${F_DETAIL[i]}"
            J+=","; jkey recommendation; jstr "${F_REC[i]}"
            J+="}"
            flush_json
        done
    done
    J+="]"

    J+=","; jkey warnings; J+="["
    first=1
    for i in "${!WARNINGS[@]}"; do
        (( first )) || J+=","
        first=0
        jstr "${WARNINGS[i]}"
    done
    J+="]"

    J+=","; jkey errors; J+="["
    first=1
    for i in "${!ERRORS[@]}"; do
        (( first )) || J+=","
        first=0
        jstr "${ERRORS[i]}"
    done
    J+="]"

    J+="}"
    flush_json
}

write_json() {
    local dir

    dir=$(dirname -- "$JSON_PATH")
    mkdir -p -- "$dir" || die "Cannot create directory: $dir"

    if (( SHOW_HASHES )); then
        ( umask 077; : > "$JSON_PATH" ) || die "Cannot write: $JSON_PATH"
        chmod 600 -- "$JSON_PATH" 2>/dev/null
    fi

    exec 3> "$JSON_PATH" || die "Cannot write: $JSON_PATH"
    build_json
    printf '\n' >&3
    exec 3>&-

    printf 'JSON report saved: %s' "$JSON_PATH"
    (( SHOW_HASHES )) && printf ' (mode 600, contains password hashes)'
    printf '\n'
}

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------

main() {
    parse_args "$@"

    NOW=${USER_AUDITOR_NOW:-$(date +%s)}
    TODAY=$(( NOW / 86400 ))
    STARTED_AT=$(date -u -d "@$NOW" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)

    if [[ -z $ROOT ]]; then
        HOST_NAME=$(hostname 2>/dev/null || echo unknown)
    elif [[ -r $ROOT/etc/hostname ]]; then
        read -r HOST_NAME < "$ROOT/etc/hostname" || HOST_NAME=unknown
        HOST_NAME=${HOST_NAME//[[:cntrl:]]/?}
    else
        HOST_NAME=unknown
    fi

    load_login_defs
    parse_passwd
    parse_shadow
    parse_group

    if (( ${#ERRORS[@]} > 0 )); then
        printf 'Error: %s\n' "${ERRORS[@]}" >&2
        die "Cannot continue: required files are missing under ${ROOT:-/}."
    fi

    evaluate_accounts
    check_accounts
    load_sudoers
    (( SUDOERS_LOADED )) || fallback_sudo_groups
    check_sshd
    check_login_defs

    if (( CHECK_PERMISSIONS )); then check_permissions; fi
    if (( CHECK_HOMES )); then check_homes; fi
    if (( CHECK_ACTIVITY )); then check_activity; fi

    count_all_findings
    print_report

    if [[ -n $JSON_PATH ]]; then
        printf '\n'
        write_json
    fi

    if [[ -n $FAIL_ON ]]; then
        local sev i threshold
        sevn "$FAIL_ON"
        threshold=$SEVN

        for (( i = 0; i < ${#F_SEV[@]}; i++ )); do
            if (( ${SEV_NUM[${F_SEV[i]}]} >= threshold )); then
                exit 1
            fi
        done
    fi

    exit 0
}

main "$@"