#!/bin/bash

RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
BLUE='\e[1;34m'
CYAN='\e[1;36m'
MAGENTA='\e[1;35m'
RESET='\e[0m'


check_dependencies() {
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}[ERROR] 'jq' is not installed. Please install it to parse JSON outputs.${RESET}"
        exit 1
    fi
    if ! command -v md5sum &> /dev/null; then
        echo -e "${RED}[ERROR] 'md5sum' is not installed. Required for tracking new leaks.${RESET}"
        exit 1
    fi
}

# 1. Option: Hunting
run_hunting() {
    echo ""
    read -p "$(echo -e ${CYAN}"[?] Enter the keyword file (e.g., list.txt): "${RESET})" kw_file
    
    if [[ ! -f "$kw_file" ]]; then
        echo -e "${RED}[ERROR] File '$kw_file' not found!${RESET}"
        return
    fi

    read -p "$(echo -e ${CYAN}"[?] Enter the client name: "${RESET})" client
    
    mkdir -p "$client"

    echo -e "${BLUE}[INFO] Starting hunting process for client: ${YELLOW}$client${RESET}"
    
    
    while IFS= read -r keyword || [[ -n "$keyword" ]]; do
        [[ -z "$keyword" ]] && continue
        
        echo -e "${MAGENTA}[*] Processing keyword: ${YELLOW}$keyword${RESET}"
        
        temp_dir="temp_$(date +%s)"
        mkdir -p "$temp_dir"

        postleaks -k "$keyword" --output "$temp_dir/"

        count=1
        for json_file in "$temp_dir"/*.json; do
            if [[ -f "$json_file" ]]; then
                new_name="${keyword//./_}"
                if [[ $count -eq 1 ]]; then
                    mv "$json_file" "${client}/${new_name}.json"
                else
                    mv "$json_file" "${client}/${new_name}_${count}.json"
                fi
                ((count++))
            fi
        done

        rm -rf "$temp_dir"
        
    done < "$kw_file"
    
    echo -e "${GREEN}[SUCCESS] Hunting completed. Results stored in '${client}/'${RESET}"
}

# 2. Option: Show Results (Only New)
show_results() {
    echo ""
    read -p "$(echo -e ${CYAN}"[?] Enter the client/folder name to analyze: "${RESET})" target_dir
    
    if [[ ! -d "$target_dir" ]]; then
        echo -e "${RED}[ERROR] Directory '$target_dir' not found!${RESET}"
        return
    fi

    hash_db="${target_dir}/.known_hashes.txt"
    touch "$hash_db" # Ensure it exists

    echo ""
    echo -e "${BLUE}==========================================================${RESET}"
    echo -e "${GREEN}                       NEW RESULTS                       ${RESET}"
    echo -e "${BLUE}==========================================================${RESET}"

    C_KEY=$(printf '\033[1;36m')
    C_VAL=$(printf '\033[1;32m')
    C_HDR=$(printf '\033[1;33m')
    C_RST=$(printf '\033[0m')

    local found_new=0
    local new_hashes=()

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue

        # Generate a unique string based on Method, URL, and Headers to create a footprint
        raw_content=$(jq -r '
            "\(.method // "")|\(.url // "")|" + 
            (.headerData // [] | map("\(.key // ""):\(.value // "")") | join(","))
        ' "$file")
        
        # Calculate MD5 hash of the footprint
        leak_hash=$(echo -n "$raw_content" | md5sum | awk '{print $1}')

        # Check if the hash is already in our known database
        if grep -q "$leak_hash" "$hash_db"; then
            continue
        fi

        found_new=1
        new_hashes+=("$leak_hash")

        echo -e "${YELLOW}SOURCE FILE: $(basename "$file")${RESET}"
        echo -e "${BLUE}----------------------------------------------------------${RESET}"
        
        jq -r \
            --arg c_key "$C_KEY" \
            --arg c_val "$C_VAL" \
            --arg c_hdr "$C_HDR" \
            --arg c_rst "$C_RST" '
            "\($c_key)NAME:\($c_rst)   \($c_val)\(.name // "N/A")\($c_rst)",
            "\($c_key)METHOD:\($c_rst) \($c_val)\(.method // "N/A")\($c_rst)",
            "\($c_key)URL:\($c_rst)    \($c_val)\(.url // "N/A")\($c_rst)",
            "\($c_hdr)HEADERS:\($c_rst)",
            (.headerData // [] | .[] | "  - \($c_key)Key:\($c_rst) \($c_val)\(.key)\($c_rst) | \($c_key)Value:\($c_rst) \($c_val)\(.value)\($c_rst) | \($c_key)Type:\($c_rst) \($c_val)\(.type)\($c_rst)"),
            ""
        ' "$file"
        
        echo -e "${BLUE}==========================================================${RESET}"
        
    done < <(find "$target_dir" -maxdepth 1 -type f -name "*.json")

    if [[ $found_new -eq 0 ]]; then
        echo -e "${YELLOW}[INFO] No new leaks found. Everything is already reported/known.${RESET}"
    else
        echo ""
        read -p "$(echo -e ${CYAN}"[?] Do you want to mark these ${#new_hashes[@]} results as reported? (y/n): "${RESET})" mark_seen
        
        if [[ "$mark_seen" =~ ^[Yy]$ ]]; then
            for h in "${new_hashes[@]}"; do
                echo "$h" >> "$hash_db"
            done
            echo -e "${GREEN}[SUCCESS] Hashes saved. These won't be shown again.${RESET}"
        else
            echo -e "${YELLOW}[INFO] Hashes NOT saved. They will appear again next time you run Option 2.${RESET}"
        fi
    fi
}


check_dependencies

while true; do
    echo ""
    echo -e "${MAGENTA}=======================================${RESET}"
    echo -e "${YELLOW}       Postman Leak Recon Tool         ${RESET}"
    echo -e "${MAGENTA}=======================================${RESET}"
    echo -e "${CYAN}1.${RESET} Hunting"
    echo -e "${CYAN}2.${RESET} Show Results"
    echo -e "${CYAN}3.${RESET} Exit"
    echo -e "${MAGENTA}=======================================${RESET}"
    read -p "$(echo -e ${YELLOW}"[?] Choose an option (1-3): "${RESET})" option

    case $option in
        1) run_hunting ;;
        2) show_results ;;
        3) echo -e "${GREEN}[INFO] Exiting...${RESET}"; exit 0 ;;
        *) echo -e "${RED}[ERROR] Invalid option.${RESET}" ;;
    esac
done
