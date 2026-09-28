#!/bin/bash

# Color codes for clean and professional look
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

clear

echo -e "${CYAN}========================================="
echo -e "       ADVANCED SHODANX AUTOMATION       "
echo -e "=========================================${NC}"
echo ""

# Handle optional -o flag from arguments if provided
OUTPUT_FILE="finding.txt"
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -o|--output) OUTPUT_FILE="$2"; shift ;;
        *) echo -e "${RED}[-] Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

# Check if shodanx is installed
if ! command -v shodanx &> /dev/null; then
    echo -e "${RED}[-] Error: 'shodanx' tool is not installed or not in PATH.${NC}"
    exit 1
fi

# 1. Ask for Shodan Dork (Loop until valid input is given)
while true; do
    echo -e "${YELLOW}[?] Enter your Shodan dork${NC}"
    read -p "➜ " dork_query
    if [ -n "$dork_query" ]; then
        break
    fi
    echo -e "${RED}[!] Error: Shodan dork cannot be empty. Please try again.${NC}\n"
done

# 2. Ask for Host / Domain (Loop until valid input is given)
while true; do
    echo -e "\n${YELLOW}[?] Enter target domain or domain list file${NC}"
    read -p "➜ " target_input
    if [ -n "$target_input" ]; then
        break
    fi
    echo -e "${RED}[!] Error: Target input cannot be empty. Please try again.${NC}\n"
done

# 3. Ask for Output file name (Optional, leaves default if blank)
echo -e "\n${YELLOW}[?] Enter output file name (Leave blank for 'finding.txt')${NC}"
read -p "➜ " custom_output

if [ -n "$custom_output" ]; then
    OUTPUT_FILE="$custom_output"
fi

# Temporary file to capture raw output and filter out tool banners
TEMP_FILE=$(mktemp)

echo -e "\n${CYAN}[+] Starting scan...${NC}\n"

total_scanned=0

# Function to run the scan
run_scan() {
    local domain="$1"
    echo -e "${CYAN}[*] Scanning target:${NC} $domain"
    
    # Run shodanx and capture output
    shodanx custom -cq "$dork_query hostname:\"$domain\"" >> "$TEMP_FILE"
    
    ((total_scanned++))
}

# Check if the target input is a file or a single domain
if [ -f "$target_input" ]; then
    echo -e "${GREEN}[+] File detected. Reading domains from: $target_input${NC}\n"
    while IFS= read -r domain || [ -n "$domain" ]; do
        domain=$(echo "$domain" | xargs)
        if [ -z "$domain" ] || [[ "$domain" =~ ^# ]]; then
            continue
        fi
        run_scan "$domain"
        sleep 1
    done < "$target_input"
else
    # Treat as a single domain
    run_scan "$target_input"
fi

# Clean the output: Remove shodanx ASCII banners, version lines, and empty lines
# Keep only real assets/findings
grep -vE "RevoltSecurities|version|shodanx|---|\[\+\]|\[\*\]" "$TEMP_FILE" | grep -v '^[[:space:]]*$' > "$OUTPUT_FILE"

# Check if the output file has actual content
if [ -s "$OUTPUT_FILE" ]; then
    # Content found, show on screen and keep file
    cat "$OUTPUT_FILE"
    echo -e "\n${CYAN}========================================="
    echo -e "${GREEN}[+] Scan Completed! Results saved in: $OUTPUT_FILE${NC}"
    echo -e "${CYAN}[*] Total Targets Scanned:${NC} $total_scanned"
    echo -e "${CYAN}========================================="
else
    # No content found, delete the empty/useless file
    rm -f "$OUTPUT_FILE"
    echo -e "\n${CYAN}========================================="
    echo -e "${YELLOW}[-] No matching assets found. File not saved.${NC}"
    echo -e "${CYAN}[*] Total Targets Scanned:${NC} $total_scanned"
    echo -e "${CYAN}========================================="
fi

# Clean up temporary file
rm -f "$TEMP_FILE"
