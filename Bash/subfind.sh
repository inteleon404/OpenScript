#!/usr/bin/env bash

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'
BLUE='\033[1;94m'
PINK='\033[1;95m'
LIME='\033[38;5;118m'
ORANGE='\033[38;5;214m'

HOME_DIR="${HOME:-$(eval echo "~$USER")}"
GOBIN_DIR="${GOBIN:-$HOME_DIR/go/bin}"
export GOBIN="$GOBIN_DIR"
export PATH="$GOBIN_DIR:$HOME_DIR/.astral/bin:$HOME_DIR/.cargo/bin:$HOME_DIR/.local/bin:/usr/local/bin:$PATH"

TEMP_RESULTS="temp-sub.txt"
DEFAULT_OUTPUT="sub.txt"
GITHUB_SUBDOMAINS_TOKEN="${GITHUB_SUBDOMAINS_TOKEN:-github_pat_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}"
USE_FX=0
[[ -t 1 ]] && USE_FX=1
IS_WSL=0
IS_KALI=0
PLATFORM_LABEL="Linux"
PUREDNS_WORDLIST="${SUBFIND_WORDLIST:-}"
PUREDNS_RESOLVERS="${SUBFIND_RESOLVERS:-}"
LOCAL_DATA_DIR="$HOME_DIR/.local/share/subfind"
DEFAULT_RESOLVERS=(
    "1.1.1.1:53"
    "8.8.8.8:53"
    "9.9.9.9:53"
    "8.8.4.4:53"
)

DEPENDENCIES=(
    git curl wget unzip go subfinder jq assetfinder subdominator
    shodanx findomain bbot github-subdomains massdns puredns dnsx unew subdog
)

ENUM_TOOLS=(
    subfinder puredns assetfinder subdominator
    shodanx findomain bbot github-subdomains subdog
)
OUT_OF_SCOPE_RULES=()

animate_help_intro() {
    local msg="$1"
    local frames='⣾⣽⣻⢿⡿⣟⣯⣷'
    local frame
    local i

    if [[ "$USE_FX" -ne 1 ]]; then
        echo -e "${BLUE}${BOLD}[INFO]${NC} ${msg}"
        return 0
    fi

    for ((i=0; i<20; i++)); do
        frame="${frames:i%8:1}"
        printf "\r${PINK}${BOLD}[%s]${NC} %s" "$frame" "$msg"
        sleep 0.04
    done
    printf "\r${LIME}${BOLD}[✔]${NC} %s\n" "$msg"
}

help_line() {
    local color="$1"
    shift
    local msg="$*"
    local i

    if [[ "$USE_FX" -eq 1 ]]; then
        printf "%b" "$color"
        for ((i=0; i<${#msg}; i++)); do
            printf "%s" "${msg:i:1}"
            sleep 0.0015
        done
        printf "%b\n" "$NC"
    else
        printf "%b%s%b\n" "$color" "$msg" "$NC"
    fi
}

print_usage() {
    local enum_tools
    enum_tools="$(printf '%s, ' "${ENUM_TOOLS[@]}")"
    enum_tools="${enum_tools%, }"

    animate_help_intro "Loading subfind advanced help system"
    
    echo -e "${PINK}${BOLD}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PINK}${BOLD}║${LIME}              SUBFIND - High-Performance Subdomain Discovery          ${PINK}${BOLD}║${NC}"
    echo -e "${PINK}${BOLD}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    
    help_line "$CYAN" "DESCRIPTION:"
    help_line "$NC"   "  A powerful wrapper for modern subdomain enumeration tools. It automates"
    help_line "$NC"   "  passive discovery, active bruteforcing, and validates findings with dnsx."
    help_line "$CYAN" ""
    
    help_line "$CYAN" "USAGE:"
    help_line "$GREEN" "  subfind [options]"
    help_line "$CYAN" ""
    
    help_line "$CYAN" "CORE OPTIONS:"
    help_line "$YELLOW" "  -d, --domain <domain>    Target a single domain (e.g., example.com)"
    help_line "$YELLOW" "  -f, --file <path>        Path to a file containing domains (one per line)"
    help_line "$YELLOW" "  -o, --output <path>      Output file path (default: sub.txt)"
    help_line "$YELLOW" "  -oos, --out-of-scope <f> Path to file containing out-of-scope targets"
    help_line "$CYAN" ""
    
    help_line "$CYAN" "INFORMATION:"
    help_line "$YELLOW" "  -h, --help               Show this premium help menu"
    help_line "$CYAN" ""
    
    help_line "$CYAN" "ENVIRONMENT VARIABLES:"
    help_line "$ORANGE" "  GITHUB_SUBDOMAINS_TOKEN  Token for GitHub subdomain discovery"
    help_line "$ORANGE" "  SUBFIND_WORDLIST         Path to a custom DNS bruteforce wordlist"
    help_line "$ORANGE" "  SUBFIND_RESOLVERS        Path to a custom DNS resolvers file"
    help_line "$CYAN" ""
    
    help_line "$CYAN" "TOOLS INCLUDED:"
    help_line "$LIME"   "  Passive:  subfinder, assetfinder, subdominator, shodanx,"
    help_line "$LIME"   "            findomain, bbot, github-subdomains, subdog"
    help_line "$LIME"   "  Active:   puredns (Bruteforce and wildcard filtering; requires massdns)"
    help_line "$LIME"   "  Utility:  dnsx (Validation), unew (Deduplication)"
    help_line "$CYAN" ""
    
    help_line "$CYAN" "SCOPE FILTERING (-oos):"
    help_line "$NC"   "  The out-of-scope file should contain one entry per line."
    help_line "$NC"   "  Supported formats:"
    help_line "$YELLOW" "    domain.com          Exclude exact domain"
    help_line "$YELLOW" "    *.domain.com        Exclude all subdomains of domain.com"
    help_line "$CYAN" ""
    
    help_line "$CYAN" "EXAMPLES:"
    help_line "$GREEN" "  subfind -d example.com"
    help_line "$GREEN" "  subfind -f targets.txt -o results.txt"
    help_line "$GREEN" "  subfind -d example.com -oos out-of-scope.txt"
    help_line "$CYAN" ""
    
    echo -e "${PINK}${BOLD}╚══════════════════════════════════════════════════════════════════════╝${NC}"
}

detect_platform() {
    if grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null || [[ -n "${WSL_DISTRO_NAME:-}" || -n "${WSL_INTEROP:-}" ]]; then
        IS_WSL=1
        PLATFORM_LABEL="WSL"
    fi

    if [[ -r /etc/os-release ]] && grep -qi '^ID=kali' /etc/os-release; then
        IS_KALI=1
        if [[ "$IS_WSL" -eq 1 ]]; then
            PLATFORM_LABEL="WSL + Kali"
        else
            PLATFORM_LABEL="Kali Linux"
        fi
    fi
}

ensure_wordlist() {
    local fallback_file="$LOCAL_DATA_DIR/wordlists/subdomains-top1million-110000.txt"
    local -a candidates=()
    local candidate

    if [[ -n "$PUREDNS_WORDLIST" ]]; then
        candidates+=("$PUREDNS_WORDLIST")
    fi

    candidates+=(
        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
        "$HOME_DIR/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        "$HOME_DIR/.local/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        "$fallback_file"
    )

    for candidate in "${candidates[@]}"; do
        if [[ -s "$candidate" ]]; then
            PUREDNS_WORDLIST="$candidate"
            return 0
        fi
    done

    mkdir -p "$(dirname "$fallback_file")"
    print_stage "$YELLOW" "FETCH" "SecLists wordlist not found. Downloading fallback list..."
    curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" -o "$fallback_file" || {
        echo -e "${RED}${BOLD}Failed to download fallback wordlist.${NC}"
        return 1
    }

    PUREDNS_WORDLIST="$fallback_file"
    return 0
}

ensure_resolvers() {
    local fallback_file="$LOCAL_DATA_DIR/resolvers.txt"
    local dedup_file
    local candidate
    local resolver
    local -a candidates=(
        "$PUREDNS_RESOLVERS"
        "$HOME_DIR/resolvers.txt"
        "$HOME_DIR/.config/puredns/resolvers.txt"
        "$HOME_DIR/.config/subfinder/resolvers.txt"
        "$HOME_DIR/.local/share/subfinder/resolvers.txt"
    )

    for candidate in "${candidates[@]}"; do
        if [[ -n "$candidate" && -s "$candidate" ]]; then
            PUREDNS_RESOLVERS="$candidate"
            return 0
        fi
    done

    mkdir -p "$(dirname "$fallback_file")"
    awk '/^nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null \
        | grep -E '^[0-9a-fA-F:.]+$' \
        | sed '/^[[:space:]]*$/d' \
        | sed '/:53$/! s/$/:53/' \
        > "$fallback_file"

    for resolver in "${DEFAULT_RESOLVERS[@]}"; do
        printf '%s\n' "$resolver" >> "$fallback_file"
    done

    dedup_file="$(mktemp)" || return 1
    if command -v unew >/dev/null 2>&1 && unew "$dedup_file" < "$fallback_file" 2>/dev/null; then
        :
    else
        sort -u "$fallback_file" > "$dedup_file"
    fi
    mv "$dedup_file" "$fallback_file"

    PUREDNS_RESOLVERS="$fallback_file"
    return 0
}

prepare_runtime_assets() {
    ensure_wordlist || exit 1
    ensure_resolvers || exit 1
    print_stage "$GREEN" "ASSET" "Wordlist: $PUREDNS_WORDLIST"
    print_stage "$GREEN" "ASSET" "Resolvers: $PUREDNS_RESOLVERS"
}

resolve_pip_command() {
    if command -v pip3 >/dev/null 2>&1; then
        echo "pip3"
        return 0
    fi

    if command -v pip >/dev/null 2>&1; then
        echo "pip"
        return 0
    fi

    sudo apt-get install -y python3-pip >/dev/null 2>&1 || return 1
    if command -v pip3 >/dev/null 2>&1; then
        echo "pip3"
        return 0
    fi

    return 1
}

print_stage() {
    local color="$1"
    local label="$2"
    local msg="$3"
    echo -e "${color}${BOLD}[${label}]${NC} ${msg}"
}

animate_status() {
    local msg="$1"
    local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local color_array=("$RED" "$GREEN" "$YELLOW" "$BLUE" "$PINK" "$CYAN" "$LIME" "$ORANGE")
    local frame
    local i
    local c

    if [[ "$USE_FX" -ne 1 ]]; then
        print_stage "$BLUE" "INFO" "$msg"
        return 0
    fi

    for ((i=0; i<15; i++)); do
        frame="${frames:i%10:1}"
        c="${color_array[i%8]}"
        printf "\r${c}${BOLD}[%s]${NC} %s" "$frame" "$msg"
        sleep 0.05
    done
    printf "\r${LIME}${BOLD}[✔]${NC} %s\n" "$msg"
}

print_tool_progress() {
    local index="$1"
    local total="$2"
    local tool="$3"
    local domain="$4"
    local width=30
    local filled
    local empty
    local bar

    filled=$(( index * width / total ))
    empty=$(( width - filled ))
    bar="$(printf '%*s' "$filled" '' | tr ' ' '#')"
    bar+="$(printf '%*s' "$empty" '' | tr ' ' '-')"

    echo -e "${PINK}${BOLD}[${index}/${total}]${NC} ${LIME}[${bar}]${NC} ${CYAN}${BOLD}${tool}${NC} ${PINK}->${NC} ${YELLOW}${domain}${NC}"
}

ensure_lolcat() {
    if command -v lolcat >/dev/null 2>&1; then
        return 0
    fi

    echo "Installing lolcat..."
    sudo apt-get update -y >/dev/null 2>&1
    sudo apt-get install -y lolcat >/dev/null 2>&1 || pip3 install lolcat >/dev/null 2>&1 || true
    if command -v lolcat >/dev/null 2>&1; then
        animate_status "lolcat installed"
    fi
}

animate_hacker_typing() {
    local color="$1"
    local msg="$2"
    local delay="${3:-0.03}"
    local i
    
    if [[ "$USE_FX" -ne 1 ]]; then
        echo -e "${color}${msg}${NC}"
        return 0
    fi
    
    printf "%b" "$color"
    for ((i=0; i<${#msg}; i++)); do
        printf "%s" "${msg:i:1}"
        sleep "$delay"
    done
    printf "%b\n" "$NC"
}

print_banner() {
    if [[ "$USE_FX" -eq 1 ]]; then
        local chars="01"
        for i in {1..7}; do
            local line=""
            for j in {1..60}; do
                line="${line}${chars:RANDOM%${#chars}:1} "
            done
            printf "\r\033[38;5;46m${line}\033[0m"
            sleep 0.05
        done
        printf "\r\033[K"
    fi

    local banner_text
    banner_text=$(cat << "EOF"
 ________  ___  ___  ________  ________ ___  ________   ________     
|\   ____\|\  \|\  \|\   __  \|\  _____|\  \|\   ___  \|\   ___ \    
\ \  \___|\ \  \\\  \ \  \|\ /\ \  \__/\ \  \ \  \\ \  \ \  \_|\ \   
 \ \_____  \ \  \\\  \ \   __  \ \   __\\ \  \ \  \\ \  \ \  \ \\ \  
  \|____|\  \ \  \\\  \ \  \|\  \ \  \_| \ \  \ \  \\ \  \ \  \_\\ \ 
    ____\_\  \ \_______\ \_______\ \__\   \ \__\ \__\\ \__\ \_______\
   |\_________\|_______|\|_______|\|__|    \|__|\|__| \|_____________\
EOF
    )

    if command -v lolcat >/dev/null 2>&1; then
        {
            echo -e "\033[1;31m\033[1m${banner_text}"
            echo -e "\033[1;33m\033[1m--------------------------------------------\033[0m"
            echo -e "\033[1;36m\033[1m           Made by @Bytes_Knight\033[0m"
            echo -e "\033[1;33m\033[1m--------------------------------------------\033[0m"
        } | lolcat
    else
        echo -e "${RED}${BOLD}${banner_text}${NC}"
        echo -e "${YELLOW}${BOLD}--------------------------------------------${NC}"
        echo -e "${CYAN}${BOLD}           Made by @Bytes_Knight${NC}"
        echo -e "${YELLOW}${BOLD}--------------------------------------------${NC}"
    fi
    
    if [[ "$USE_FX" -eq 1 ]]; then
        animate_hacker_typing "$LIME" "[+] INITIALIZING NEURAL NETWORK..." 0.02
        animate_hacker_typing "$CYAN" "[+] BYPASSING FIREWALLS..." 0.02
        animate_hacker_typing "$PINK" "[+] ENGAGING ENUMERATION ENGINES..." 0.02
        sleep 0.2
    fi
}

ensure_uv() {
    export PATH="$GOBIN_DIR:$HOME_DIR/.astral/bin:$HOME_DIR/.cargo/bin:$HOME_DIR/.local/bin:/usr/local/bin:$PATH"

    if command -v uv >/dev/null 2>&1; then
        return 0
    fi

    local uv_bin
    for uv_bin in "$HOME_DIR/.astral/bin/uv" "$HOME_DIR/.cargo/bin/uv" "$HOME_DIR/.local/bin/uv" "/root/.astral/bin/uv" "/root/.cargo/bin/uv"; do
        if [[ -x "$uv_bin" ]]; then
            export PATH="$(dirname "$uv_bin"):$PATH"
            sudo cp "$uv_bin" /usr/local/bin/ 2>/dev/null || true
            return 0
        fi
    done

    print_stage "$CYAN" "INSTALL" "Installing uv package manager..."
    curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || \
    wget -qO- https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true

    export PATH="$GOBIN_DIR:$HOME_DIR/.astral/bin:$HOME_DIR/.cargo/bin:$HOME_DIR/.local/bin:/usr/local/bin:$PATH"

    if command -v uv >/dev/null 2>&1; then
        return 0
    fi

    for uv_bin in "$HOME_DIR/.astral/bin/uv" "$HOME_DIR/.cargo/bin/uv" "$HOME_DIR/.local/bin/uv" "/root/.astral/bin/uv" "/root/.cargo/bin/uv"; do
        if [[ -x "$uv_bin" ]]; then
            export PATH="$(dirname "$uv_bin"):$PATH"
            sudo cp "$uv_bin" /usr/local/bin/ 2>/dev/null || true
            return 0
        fi
    done

    local pip_cmd
    if pip_cmd="$(resolve_pip_command 2>/dev/null)"; then
        "$pip_cmd" install uv --break-system-packages >/dev/null 2>&1 || true
        if command -v uv >/dev/null 2>&1; then
            return 0
        fi
    fi

    sudo apt-get install -y uv >/dev/null 2>&1 || true
    if command -v uv >/dev/null 2>&1; then
        return 0
    fi

    return 1
}

install_dependency() {
    local dep="$1"
    local pip_cmd

    echo -e "${CYAN}${BOLD}Installing $dep...${NC}"
    case "$dep" in
        go)
            sudo apt-get update -y >/dev/null 2>&1
            sudo apt-get install -y golang-go || sudo apt-get install -y golang || return 1
            ;;
        subfinder)
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || return 1
            sudo cp "$GOBIN_DIR/subfinder" /usr/local/bin/ 2>/dev/null || true
            ;;
        assetfinder)
            go install github.com/tomnomnom/assetfinder@latest || return 1
            sudo cp "$GOBIN_DIR/assetfinder" /usr/local/bin/ 2>/dev/null || true
            ;;
        jq)
            sudo apt-get install -y jq || return 1
            ;;
        subdominator)
            if ensure_uv; then
                uv tool install git+https://github.com/RevoltSecurities/Subdominator.git || \
                { pip_cmd="$(resolve_pip_command)" && "$pip_cmd" install git+https://github.com/RevoltSecurities/Subdominator.git --break-system-packages; } || return 1
            else
                pip_cmd="$(resolve_pip_command)" || return 1
                "$pip_cmd" install git+https://github.com/RevoltSecurities/Subdominator.git --break-system-packages || return 1
            fi
            ;;
        shodanx)
            pip_cmd="$(resolve_pip_command)" || {
                echo -e "${RED}${BOLD}python3-pip is required for ShodanX setup.${NC}"
                return 1
            }
            "$pip_cmd" install git+https://github.com/RevoltSecurities/ShodanX.git --break-system-packages 2>/dev/null || {
                git clone https://github.com/RevoltSecurities/ShodanX.git || return 1
                (
                    cd ShodanX || exit 1
                    "$pip_cmd" install -r requirements.txt --break-system-packages || exit 1
                    sudo python3 setup.py install || exit 1
                )
                local status=$?
                rm -rf ShodanX
                [[ $status -eq 0 ]] || return 1
            }
            ;;
        findomain)
            wget "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip" -O findomain-linux.zip 2>/dev/null || \
            wget "https://github.com/Findomain/Findomain/releases/download/10.0.1/findomain-linux.zip" -O findomain-linux.zip || return 1
            unzip -o findomain-linux.zip || return 1
            chmod +x findomain || return 1
            cp findomain "$GOBIN_DIR/" 2>/dev/null || true
            sudo cp findomain /usr/local/bin/ 2>/dev/null || true
            rm -f findomain-linux.zip findomain
            ;;
        bbot)
            if ensure_uv; then
                uv tool install git+https://github.com/blacklanternsecurity/bbot.git --force || \
                { pip_cmd="$(resolve_pip_command)" && "$pip_cmd" install bbot --break-system-packages; } || return 1
            else
                pip_cmd="$(resolve_pip_command)" || return 1
                "$pip_cmd" install bbot --break-system-packages || return 1
            fi
            ;;
        github-subdomains)
            go install github.com/gwen001/github-subdomains@latest || return 1
            sudo cp "$GOBIN_DIR/github-subdomains" /usr/local/bin/ 2>/dev/null || true
            ;;
        puredns)
            go install github.com/d3mondev/puredns/v2@latest || return 1
            sudo cp "$GOBIN_DIR/puredns" /usr/local/bin/ 2>/dev/null || true
            ;;
        dnsx)
            go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || return 1
            sudo cp "$GOBIN_DIR/dnsx" /usr/local/bin/ 2>/dev/null || true
            ;;
        subdog)
            go install github.com/rix4uni/subdog@latest || return 1
            sudo cp "$GOBIN_DIR/subdog" /usr/local/bin/ 2>/dev/null || true
            ;;
        unew)
            go install github.com/rix4uni/unew@latest || return 1
            sudo cp "$GOBIN_DIR/unew" /usr/local/bin/ 2>/dev/null || true
            ;;
        *)
            sudo apt-get install -y "$dep" || return 1
            ;;
    esac
}

check_dependencies() {
    local missing_dependencies=()
    local dep

    mkdir -p "$GOBIN_DIR" "$HOME_DIR/.astral/bin" "$HOME_DIR/.local/bin" "$HOME_DIR/.cargo/bin"
    export GOBIN="$GOBIN_DIR"
    export PATH="$GOBIN_DIR:$HOME_DIR/.astral/bin:$HOME_DIR/.cargo/bin:$HOME_DIR/.local/bin:/usr/local/bin:$PATH"

    for dep in "${DEPENDENCIES[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            echo -e "${RED}${BOLD}$dep is not installed.${NC}"
            missing_dependencies+=("$dep")
        fi
    done

    if [[ ${#missing_dependencies[@]} -eq 0 ]]; then
        print_stage "$GREEN" "READY" "All dependencies are already installed."
        return 0
    fi

    print_stage "$CYAN" "SYNC" "Updating package lists..."
    sudo apt-get update -y || {
        echo -e "${RED}${BOLD}Failed to update package lists.${NC}"
        exit 1
    }

    for dep in "${missing_dependencies[@]}"; do
        install_dependency "$dep" || {
            echo -e "${RED}${BOLD}Failed to install dependency: $dep${NC}"
            exit 1
        }
    done

    export PATH="$GOBIN_DIR:$HOME_DIR/.astral/bin:$HOME_DIR/.cargo/bin:$HOME_DIR/.local/bin:/usr/local/bin:$PATH"
    print_stage "$GREEN" "DONE" "All missing dependencies have been installed."
}

check_internet() {
    local targets=(cloudflare.com google.com bing.com yahoo.com baidu.com)
    local random_target="${targets[RANDOM % ${#targets[@]}]}"
    ping -c 1 "$random_target" >/dev/null 2>&1
    return $?
}

wait_for_internet() {
    if check_internet; then
        return 0
    fi

    print_stage "$RED" "ALERT" "Internet is down. Pausing tasks."
    while ! check_internet; do
        echo -e "${YELLOW}${BOLD}[WAIT]${NC} Still offline... waiting 10 seconds."
        sleep 10
    done
    animate_status "Internet is back. Resuming scans"
}

escape_regex() {
    printf '%s' "$1" | sed 's/[][(){}.^$*+?|\\/]/\\&/g'
}

sanitize_domain_stream() {
    local domain="$1"
    local escaped_domain
    escaped_domain="$(escape_regex "$domain")"

    sed $'s/\x1b\\[[0-9;]*m//g' \
        | grep -Eo "([a-zA-Z0-9_-]+\.)+${escaped_domain}" \
        | grep -F "$domain" \
        | grep -Fxv "$domain" \
        | grep -Fv "@" \
        | grep -Fv "*." \
        | grep -Fv -- "---" \
        | sed '/^[[:space:]]*$/d'
}

trim_value() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

# Interactive input functions removed as per request to maintain non-interactive workflow.

resolve_scope_file_path() {
    local path_input="$1"

    path_input="$(trim_value "$path_input")"
    [[ -z "$path_input" ]] && {
        printf '%s' ""
        return 0
    }

    if [[ "$path_input" == ~/* ]]; then
        path_input="$HOME_DIR/${path_input#~/}"
    fi

    if [[ "$path_input" =~ ^[A-Za-z]:\\ ]] && command -v wslpath >/dev/null 2>&1; then
        path_input="$(wslpath "$path_input" 2>/dev/null || printf '%s' "$path_input")"
    fi

    printf '%s' "$path_input"
}

normalize_scope_entry() {
    local entry="$1"

    entry="$(trim_value "$entry")"
    entry="${entry,,}"
    entry="${entry#http://}"
    entry="${entry#https://}"
    entry="${entry%%/*}"
    entry="${entry%%:*}"
    entry="${entry#.}"
    entry="${entry%.}"

    printf '%s' "$entry"
}

is_valid_scope_entry() {
    local entry="$1"

    if [[ "$entry" == \*.* ]]; then
        [[ "$entry" =~ ^\*\.[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]]
        return $?
    fi

    [[ "$entry" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]]
}

out_of_scope_rule_exists() {
    local rule="$1"
    local existing

    for existing in "${OUT_OF_SCOPE_RULES[@]}"; do
        [[ "$existing" == "$rule" ]] && return 0
    done
    return 1
}

add_out_of_scope_rule() {
    local raw_entry="$1"
    local normalized

    normalized="$(normalize_scope_entry "$raw_entry")"
    [[ -z "$normalized" ]] && return 0

    if ! is_valid_scope_entry "$normalized"; then
        print_stage "$YELLOW" "SCOPE" "Skipping invalid rule: $raw_entry"
        return 1
    fi

    if ! out_of_scope_rule_exists "$normalized"; then
        OUT_OF_SCOPE_RULES+=("$normalized")
    fi
    return 0
}

parse_out_of_scope_inline_entries() {
    local entries="$1"
    local token
    local token_trimmed

    while IFS= read -r token || [[ -n "$token" ]]; do
        token_trimmed="$(trim_value "$token")"
        [[ -z "$token_trimmed" ]] && continue

        add_out_of_scope_rule "$token_trimmed"
    done < <(printf '%s' "$entries" | tr ',' '\n')
}

load_out_of_scope_file() {
    local rules_file="$1"
    local line

    rules_file="$(resolve_scope_file_path "$rules_file")"
    [[ -z "$rules_file" ]] && return 0

    if [[ ! -f "$rules_file" ]]; then
        print_stage "$YELLOW" "SCOPE" "Out-of-scope file not found: $rules_file"
        return 1
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        add_out_of_scope_rule "$line"
    done < "$rules_file"

    return 0
}

is_host_out_of_scope() {
    local host="$1"
    local normalized_host
    local rule
    local suffix

    normalized_host="$(normalize_scope_entry "$host")"
    [[ -z "$normalized_host" ]] && return 1

    for rule in "${OUT_OF_SCOPE_RULES[@]}"; do
        if [[ "$rule" == \*.* ]]; then
            suffix="${rule#*.}"
            if [[ "$normalized_host" == *".${suffix}" && "$normalized_host" != "$suffix" ]]; then
                return 0
            fi
        elif [[ "$normalized_host" == "$rule" ]]; then
            return 0
        fi
    done

    return 1
}

filter_out_of_scope_file() {
    local result_file="$1"
    local filtered_file
    local pattern_file
    local rule
    local suffix
    local escaped_rule
    local escaped_suffix
    local total_count=0
    local removed_count=0
    local kept_count=0

    if [[ ${#OUT_OF_SCOPE_RULES[@]} -eq 0 || ! -s "$result_file" ]]; then
        return 0
    fi

    filtered_file="$(mktemp)" || {
        echo -e "${YELLOW}${BOLD}Warning: Could not allocate temp file for scope filtering.${NC}"
        return 1
    }

    pattern_file="$(mktemp)" || {
        rm -f "$filtered_file"
        echo -e "${YELLOW}${BOLD}Warning: Could not allocate pattern file for scope filtering.${NC}"
        return 1
    }

    for rule in "${OUT_OF_SCOPE_RULES[@]}"; do
        if [[ "$rule" == \*.* ]]; then
            suffix="${rule#*.}"
            escaped_suffix="$(escape_regex "$suffix")"
            printf '^.+\\.%s$\n' "$escaped_suffix" >> "$pattern_file"
        else
            escaped_rule="$(escape_regex "$rule")"
            printf '^%s$\n' "$escaped_rule" >> "$pattern_file"
        fi
    done

    total_count="$(grep -Ec '[^[:space:]]' "$result_file" || true)"
    grep -Eiv -f "$pattern_file" "$result_file" | grep -Ev '^[[:space:]]*$' > "$filtered_file" || true
    kept_count="$(grep -Ec '[^[:space:]]' "$filtered_file" || true)"
    removed_count=$((total_count - kept_count))

    mv "$filtered_file" "$result_file"
    rm -f "$pattern_file"
    print_stage "$YELLOW" "SCOPE" "Excluded $removed_count out-of-scope hosts. Remaining: $kept_count"
    return 0
}



collect_source_files() {
    local domain="$1"
    local -a files=()
    local -a bbot_files=()
    local file

    for file in subfinder.txt assetfinder.txt subdominator.txt shodanx.txt findomain.txt githubsub.txt puredns.txt subdog.txt; do
        [[ -s "$file" ]] && files+=("$file")
    done

    if [[ -d "$domain" ]]; then
        shopt -s nullglob
        bbot_files=("$domain"/*/subdomains.txt)
        shopt -u nullglob
        for file in "${bbot_files[@]}"; do
            [[ -s "$file" ]] && files+=("$file")
        done

        while IFS= read -r -d '' file; do
            [[ "$file" == "$domain"/*/subdomains.txt ]] && continue
            [[ -s "$file" ]] && files+=("$file")
        done < <(find "$domain" -type f -name "subdomains.txt" -print0 2>/dev/null)
    fi

    if [[ ${#files[@]} -gt 0 ]]; then
        printf '%s\0' "${files[@]}"
    fi
}

combine_results_for_domain() {
    local domain="$1"
    local -a source_files=()

    mapfile -d '' source_files < <(collect_source_files "$domain")
    if [[ ${#source_files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}${BOLD}Warning: No result files found to combine for $domain${NC}"
        return 0
    fi

    if command -v unew >/dev/null 2>&1; then
        cat "${source_files[@]}" 2>/dev/null \
            | sanitize_domain_stream "$domain" \
            | (unew -q "$TEMP_RESULTS" 2>/dev/null || unew "$TEMP_RESULTS" 2>/dev/null || sort -u >> "$TEMP_RESULTS")
    else
        cat "${source_files[@]}" 2>/dev/null \
            | sanitize_domain_stream "$domain" \
            | sort -u >> "$TEMP_RESULTS"
    fi
}

cleanup_domain_artifacts() {
    local domain="$1"
    rm -rf -- "$domain" subfinder.txt assetfinder.txt subdominator.txt shodanx.txt findomain.txt githubsub.txt puredns.txt subdog.txt
}

run_tool_for_domain() {
    local tool="$1"
    local domain="$2"
    local mode="$3"

    case "$tool" in
        subfinder)
            subfinder -d "$domain" -v -all -o subfinder.txt || {
                echo -e "${YELLOW}${BOLD}Warning: subfinder failed for $domain${NC}"
            }
            ;;
        puredns)
            puredns bruteforce "$PUREDNS_WORDLIST" "$domain" \
                --resolvers "$PUREDNS_RESOLVERS" \
                --write puredns.txt || {
                echo -e "${YELLOW}${BOLD}Warning: puredns failed for $domain${NC}"
            }
            ;;
        assetfinder)
            assetfinder --subs-only "$domain" | tee assetfinder.txt || {
                echo -e "${YELLOW}${BOLD}Warning: assetfinder failed for $domain${NC}"
            }
            ;;
        subdominator)
            subdominator -d "$domain" -o subdominator.txt || {
                echo -e "${YELLOW}${BOLD}Warning: subdominator failed for $domain${NC}"
            }
            ;;
        shodanx)
            shodanx subdomain -d "$domain" -o shodanx.txt || {
                echo -e "${YELLOW}${BOLD}Warning: shodanx failed for $domain${NC}"
            }
            ;;
        findomain)
            findomain -t "$domain" | tee findomain.txt || {
                echo -e "${YELLOW}${BOLD}Warning: findomain failed for $domain${NC}"
            }
            ;;
        bbot)
            yes "" | bbot -t "$domain" -p subdomain-enum -o "$domain" -rf passive -ef portscan --force || {
                echo -e "${YELLOW}${BOLD}Warning: bbot failed for $domain${NC}"
            }
            ;;
        github-subdomains)
            github-subdomains -d "$domain" -t "$GITHUB_SUBDOMAINS_TOKEN" -o githubsub.txt || {
                echo -e "${YELLOW}${BOLD}Warning: github-subdomains failed for $domain${NC}"
            }
            ;;
        subdog)
            echo "$domain" | subdog | tee subdog.txt || {
                echo -e "${YELLOW}${BOLD}Warning: subdog failed for $domain${NC}"
            }
            ;;
    esac
}

enumerate_domain() {
    local domain="$1"
    local mode="$2"
    local tool
    local total_tools="${#ENUM_TOOLS[@]}"
    local tool_index=0

    print_stage "$CYAN" "TARGET" "Enumerating subdomains for ${RED}$domain${NC}"
    for tool in "${ENUM_TOOLS[@]}"; do
        ((tool_index++))
        wait_for_internet
        print_tool_progress "$tool_index" "$total_tools" "$tool" "$domain"
        print_stage "$BLUE" "RUN" "Launching $tool"
        run_tool_for_domain "$tool" "$domain" "$mode"
    done

    animate_status "Combining results for $domain"
    combine_results_for_domain "$domain"
    sleep 1

    if [[ "$mode" == "file" ]]; then
        clear
    fi

    cleanup_domain_artifacts "$domain"
    print_stage "$GREEN" "DONE" "Finished enumerating subdomains for $domain"
}

domain_enum() {
    local domains_file="$1"
    local domain

    if [[ ! -s "$domains_file" ]]; then
        echo -e "${RED}${BOLD}Error: Input file $domains_file is empty or does not exist.${NC}"
        exit 1
    fi

    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain="${domain%%#*}"
        domain="$(normalize_scope_entry "$domain")"
        [[ -z "$domain" || "$domain" =~ ^# ]] && continue
        [[ -z "$domain" ]] && continue
        enumerate_domain "$domain" "file"
    done < "$domains_file"
}

single_domain() {
    local domain="$1"

    domain="$(normalize_scope_entry "$domain")"
    if [[ -z "$domain" ]]; then
        echo -e "${RED}${BOLD}Error: Invalid domain.${NC}"
        exit 1
    fi

    enumerate_domain "$domain" "single"
}

count_subdomains() {
    local result_file="${1:-$DEFAULT_OUTPUT}"

    if [[ -f "$result_file" ]]; then
        local count
        count="$(wc -l < "$result_file")"
        echo -e "${GREEN}${BOLD}Total subdomains found in $result_file: $count${NC}" | lolcat
    elif [[ -f "$DEFAULT_OUTPUT" ]]; then
        local count_default
        count_default="$(wc -l < "$DEFAULT_OUTPUT")"
        echo -e "${GREEN}${BOLD}Total subdomains found: $count_default${NC}" | lolcat
    else
        echo -e "${RED}${BOLD}No subdomains file found to count.${NC}" | lolcat
    fi
}

detect_platform

file=""
domain=""
output_file="$DEFAULT_OUTPUT"
show_help_only=0
oos_file=""

if [[ $# -eq 0 ]]; then
    print_usage
    exit 0
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--file)
            if [[ -z "$2" ]]; then echo -e "${RED}${BOLD}Option -f requires an argument.${NC}"; exit 1; fi
            file="$2"; shift 2
            ;;
        -d|--domain)
            if [[ -z "$2" ]]; then echo -e "${RED}${BOLD}Option -d requires an argument.${NC}"; exit 1; fi
            domain="$2"; shift 2
            ;;
        -o|--output)
            if [[ -z "$2" ]]; then echo -e "${RED}${BOLD}Option -o requires an argument.${NC}"; exit 1; fi
            output_file="$2"; shift 2
            ;;
        -oos|--out-of-scope)
            if [[ -z "$2" ]]; then echo -e "${RED}${BOLD}Option -oos requires an argument.${NC}"; exit 1; fi
            oos_file="$2"; shift 2
            ;;
        -h|--help)
            show_help_only=1; shift 1
            ;;
        *)
            echo -e "${RED}${BOLD}Invalid option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

if [[ "$show_help_only" -eq 1 ]]; then
    print_usage
    exit 0
fi

ensure_lolcat
print_banner
print_stage "$PINK" "ENV" "Running on $PLATFORM_LABEL"

if [[ -z "$file" && -z "$domain" ]]; then
    echo -e "${RED}${BOLD}Error: Target missing. Please specify either -f (file) or -d (domain).${NC}"
    print_usage
    exit 1
fi

if [[ -n "$oos_file" ]]; then
    load_out_of_scope_file "$oos_file"
    if [[ ${#OUT_OF_SCOPE_RULES[@]} -gt 0 ]]; then
        print_stage "$GREEN" "SCOPE" "Loaded ${#OUT_OF_SCOPE_RULES[@]} out-of-scope rule(s)"
    fi
fi

check_dependencies
prepare_runtime_assets
animate_status "Environment check complete"

rm -f "$TEMP_RESULTS"
touch "$TEMP_RESULTS"

if [[ -n "$file" ]]; then
    animate_status "Starting file-based enumeration"
    domain_enum "$file"
elif [[ -n "$domain" ]]; then
    animate_status "Starting single-domain enumeration"
    single_domain "$domain"
fi

rm -f "$output_file"
if [[ -s "$TEMP_RESULTS" ]]; then
    animate_status "Building final output file"
    if command -v unew >/dev/null 2>&1; then
        cat "$TEMP_RESULTS" | grep -Fv "@" | grep -Fv "*." | (unew -q "$output_file" 2>/dev/null || unew "$output_file" 2>/dev/null || sort -u > "$output_file")
    else
        cat "$TEMP_RESULTS" | grep -Fv "@" | grep -Fv "*." | sort -u > "$output_file"
    fi
else
    touch "$output_file"
fi

if [[ -s "$output_file" ]]; then
    filter_out_of_scope_file "$output_file"
fi

if [[ -s "$output_file" ]]; then
    animate_status "Filtering alive subdomains with dnsx"
    alive_tmp_file="$(mktemp)" || {
        echo -e "${YELLOW}${BOLD}Warning: Could not create temp file for dnsx filtering.${NC}"
    }

    if [[ -n "${alive_tmp_file:-}" ]]; then
        if (command -v unew >/dev/null 2>&1 && unew < "$output_file" 2>/dev/null || sort -u "$output_file") | dnsx -retry 3 | tee "$alive_tmp_file"; then
            rm -f "$output_file"
            mv "$alive_tmp_file" "$output_file"
        else
            rm -f "$alive_tmp_file"
            echo -e "${YELLOW}${BOLD}Warning: dnsx filtering failed. Keeping unfiltered results in $output_file.${NC}"
        fi
    fi
fi

rm -f "$TEMP_RESULTS"
animate_status "Cleanup complete"
count_subdomains "$output_file"
