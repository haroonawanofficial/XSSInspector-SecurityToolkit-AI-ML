import threading
import sys
import requests
import argparse
import sqlite3
import time
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urljoin
import pickle
import queue
import signal
import csv
import json
import logging
from bs4 import BeautifulSoup
import random
import os

# Add the directory containing payload_generation.py to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from payload_generation import generate_payloads
from deep_learning import DeepLearningModel
from nlp_analysis import analyze_content
from reinforcement_learning import ReinforcementLearningAgent

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for terminal colors
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\033[94m', '\033[91m', '\033[97m', '\033[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

# Setup basic logging
current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
print(f"{GREEN}[INFO]{END} Starting the XSS Scanner at {current_time}.")
requests.packages.urllib3.disable_warnings()

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.45",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36 Edge/16.16299",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 OPR/45.0.2552.898",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Vivaldi/1.8.770.50",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/15.15063",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/15.15063",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36"
]

# Database setup
def setup_database():
    connection = sqlite3.connect('xss_scan_results.db', check_same_thread=False)
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            payload TEXT NOT NULL,
            discovered_at DATETIME NOT NULL,
            method TEXT NOT NULL,
            xss_type TEXT NOT NULL,
            success INTEGER NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS training_data (
            id INTEGER PRIMARY KEY,
            url TEXT,
            param TEXT,
            payload TEXT,
            server_type TEXT,
            method TEXT,
            response_code INTEGER,
            response_time REAL,
            response_pattern TEXT,
            success INTEGER,
            content_snippet TEXT,
            vulnerable INTEGER
        )
    """)
    connection.commit()
    return connection

db_connection = setup_database()

# Ensure necessary files are created
def create_files():
    with open('training_data.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'param', 'payload', 'server_type', 'method', 'response_code', 'response_time', 'response_pattern', 'success', 'content_snippet', 'vulnerable'])
    open('total_links_audited.txt', 'w').close()
    open('found_links.txt', 'w').close()
    open('audit_links.txt', 'w').close()

create_files()

# Create logs directory
if not os.path.exists('logs'):
    os.makedirs('logs')

# Cursor animation for loading
stop_animation = False

def animate_cursor():
    cursor = "|"
    while not stop_animation:
        for _ in range(3):
            if stop_animation:
                break
            print(f"Loading{cursor}", end='\r')
            time.sleep(0.5)
            cursor = "|" if cursor == " " else " "

cursor_thread = threading.Thread(target=animate_cursor)
cursor_thread.daemon = True
cursor_thread.start()

# Queue for database operations
db_queue = queue.Queue()

# Function to handle database operations
def db_worker():
    while True:
        db_connection, query, params = db_queue.get()
        if query == "terminate":
            break
        cursor = db_connection.cursor()
        cursor.execute(query, params)
        db_connection.commit()
        db_queue.task_done()

db_thread = threading.Thread(target=db_worker)
db_thread.daemon = True
db_thread.start()

# Read targets from file
def read_target_from_file(filepath):
    with open(filepath, "r") as f:
        return [url.strip() for url in f.readlines() if url.strip()]

# Usage instructions
print("\nStep 1: Crawl the target website for URLs:")
print("python xssscanadv.py -d http://testphp.vulnweb.com --crawl")
print("\nStep 1a: Use the crawled URLs for scanning:")
print("python xssscanadv.py -l crawled_urls.txt -t 100 --duration 3600 -s --mode autounderstand --use-model --report report.html\n")

print("\nStep 2: Quickly extract and clean URLs from the Wayback Machine:")
print("python xssscanadv.py -d http://testphp.vulnweb.com --extractquick")
print("\nStep 2a: Use the cleaned URLs for scanning:")
print("python xssscanadv.py -l testphp_vulnweb_com_cleaned_urls.txt -t 100 --duration 3600 -s --mode autounderstand --use-model --report report.html\n")

print("\nStep 3: Perform a deep crawl using CommonCrawl and Wayback Machine:")
print("python xssscanadv.py -d http://testphp.vulnweb.com --deepcrawl")
print("\nStep 3a: Use the deep crawled URLs for scanning:")
print("python xssscanadv.py -l found_links.txt -t 100 --duration 3600 -s --mode autounderstand --use-model --report report.html\n")

# Argument parsing
def get_arguments():
    parser = argparse.ArgumentParser(description='Advanced XSS Reporter')
    parser.add_argument("-t", "--thread", type=int, default=50, help="Number of Threads to Use. Default=50")
    parser.add_argument("-o", "--output", help="Save Vulnerable URLs in TXT file")
    parser.add_argument("-s", "--subs", action='store_true', help="Include Results of Subdomains")
    parser.add_argument("--deepcrawl", action='store_true', help="Uses All Available APIs of CommonCrawl for Crawling URLs [**Takes Time**]")
    parser.add_argument("--crawl", action='store_true', help="Crawl the target website for URLs")
    parser.add_argument("--extractquick", action='store_true', help="Quickly extract and clean URLs")
    parser.add_argument("--report", help="Generate an HTML report", default=None)
    parser.add_argument("--duration", type=int, help="Duration in seconds to run the scan before auto-kill")
    parser.add_argument("--mode", choices=["finetune", "autounderstand"], default="autounderstand", help="Fine-tune manually or auto-understand")
    parser.add_argument("--blind-xss-endpoint", help="Public endpoint to check for Blind XSS payload execution")
    parser.add_argument("--use-model", action='store_true', help="Use the trained model to filter URLs before scanning")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-l", "--list", help="URLs List, e.g., google_urls.txt")
    group.add_argument("-d", "--domain", help="Target Domain Name, e.g., testphp.vulnweb.com")
    return parser.parse_args()

# Function to normalize domain URL
def normalize_domain(domain):
    domain = domain.replace('http://', '').replace('https://', '').strip('/')
    return domain

# Function to fetch URLs using CommonCrawl
def fetch_urls_commoncrawl(domain):
    normalized_domain = normalize_domain(domain)
    print(f"{GREEN}[INFO]{END} Fetching URLs from CommonCrawl for domain: {normalized_domain}")
    cc_api = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url={normalized_domain}&output=json"
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    response = requests.get(cc_api, headers=headers)
    urls = []
    if response.status_code == 200:
        lines = response.text.splitlines()
        for line in lines:
            result = json.loads(line)
            urls.append(result['url'])
    else:
        print(f"{RED}[ERROR]{END} Failed to fetch URLs from CommonCrawl. Status code: {response.status_code}")
    print(f"{GREEN}[INFO]{END} Retrieved {len(urls)} URLs from CommonCrawl.")
    with open('commoncrawl_links.txt', 'w') as file:
        file.write("\n".join(urls))
    return urls

# Function to fetch URLs using Wayback Machine
def fetch_urls_wayback(domain):
    normalized_domain = normalize_domain(domain)
    print(f"{GREEN}[INFO]{END} Fetching URLs from Wayback Machine for domain: {normalized_domain}")
    wayback_api = f"http://web.archive.org/cdx/search/cdx?url={normalized_domain}/*&output=json&fl=original&collapse=urlkey"
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    response = requests.get(wayback_api, headers=headers)
    urls = []
    if response.status_code == 200:
        results = response.json()
        for result in results:
            urls.append(result[0])
    else:
        print(f"{RED}[ERROR]{END} Failed to fetch URLs from Wayback Machine. Status code: {response.status_code}")
    print(f"{GREEN}[INFO]{END} Retrieved {len(urls)} URLs from Wayback Machine.")
    with open('wayback_links.txt', 'w') as file:
        file.write("\n".join(urls))
    return urls

# Function to crawl a website for URLs
def crawl_website(domain):
    normalized_domain = normalize_domain(domain)
    print(f"{GREEN}[INFO]{END} Crawling website: {normalized_domain}")
    crawled_urls = set()
    to_crawl = queue.Queue()
    to_crawl.put(f"http://{normalized_domain}")
    crawled_urls.add(f"http://{normalized_domain}")
    headers = {'User-Agent': random.choice(USER_AGENTS)}

    while not to_crawl.empty():
        url = to_crawl.get()
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    if normalized_domain in full_url and full_url not in crawled_urls:
                        crawled_urls.add(full_url)
                        to_crawl.put(full_url)
        except Exception as e:
            print(f"{RED}[ERROR]{END} Failed to crawl {url}: {str(e)}")

    print(f"{GREEN}[INFO]{END} Crawled {len(crawled_urls)} URLs from {normalized_domain}.")
    with open('crawled_links.txt', 'w') as file:
        file.write("\n".join(crawled_urls))
    return list(crawled_urls)

def sanitize_filename(domain):
    # Remove 'http://' or 'https://' and replace non-alphanumeric characters with underscores
    sanitized = re.sub(r'http[s]?://', '', domain)
    sanitized = re.sub(r'\W+', '_', sanitized)
    return sanitized

def extract_base_url(url):
    # Extract the base URL and query parameter key to identify duplicates
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    query_params = parse_qs(parsed_url.query)
    return base_url, query_params

def fetch_and_clean_urls(domain, extensions=None, stream_output=False):
    """
    Fetch and clean URLs related to a specific domain from the Wayback Machine.

    Args:
        domain (str): The domain name to fetch URLs for.
        extensions (list): List of file extensions to check against.
        stream_output (bool): True to stream URLs to the terminal.

    Returns:
        None
    """
    logging.info(f"{YELLOW}[INFO]{END} Fetching URLs for { domain + END}")
    wayback_uri = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&collapse=urlkey&fl=original&page=/"
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    response = requests.get(wayback_uri, headers=headers)
    if response.status_code != 200:
        print(f"{RED}[ERROR]{END} Failed to fetch URLs from Wayback Machine. Status code: {response.status_code}")
        return []
    
    urls = response.text.split()
    print(f"{GREEN}[INFO]{END} Found {len(urls)} URLs for {domain}")

    # Cleaning URLs to remove duplicates based on base URL and query parameters
    seen = set()
    cleaned_urls = []
    for url in urls:
        base_url, query_params = extract_base_url(url)
        # Create a tuple of the base URL and sorted query parameter keys to identify duplicates
        unique_key = (base_url, tuple(sorted(query_params.keys())))
        if unique_key not in seen:
            seen.add(unique_key)
            cleaned_urls.append(url)
    
    print(f"{GREEN}[INFO]{END} Found {len(cleaned_urls)} URLs after cleaning")
    
    sanitized_domain = sanitize_filename(domain)
    result_file = f"{sanitized_domain}_cleaned_urls.txt"
    
    with open(result_file, "w") as f:
        for url in cleaned_urls:
            f.write(url + "\n")
            if stream_output:
                print(url)
    
    print(f"{GREEN}[INFO]{END} Saved cleaned URLs to {result_file}")
    return cleaned_urls

# Function to save training data to CSV
def save_training_data_to_csv(data):
    with open('training_data.csv', mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(data)

# Function to insert training data
def insert_training_data(url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable):
    query = """
        INSERT INTO training_data (url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    db_queue.put((db_connection, query, (url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable)))
    save_training_data_to_csv([url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable])

# Function to insert vulnerabilities data
def insert_vulnerability_data(url, payload, method, xss_type, success):
    query = """
        INSERT INTO vulnerabilities (url, payload, discovered_at, method, xss_type, success)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    db_queue.put((db_connection, query, (url, payload, datetime.now(), method, xss_type, success)))

# XSS Scanner class definition
class XSSScanner:
    def __init__(self, url_list, thread_number, report_file=None, mode="autounderstand", blind_xss_endpoint=None, use_model=False):
        self.url_list = list(set(url_list))
        self.thread_number = thread_number
        self.report_file = report_file
        self.mode = mode
        self.blind_xss_endpoint = blind_xss_endpoint
        self.use_model = use_model
        self.vulnerable_urls = []
        self.scan_results = []
        self.payloads = generate_payloads() or []
        self.methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
        self.model = DeepLearningModel() if use_model else None
        self.rl_agent = ReinforcementLearningAgent()

    def load_or_train_model(self):
        model_path = f"{normalize_domain(args.domain)}_xss_model.pkl"
        if os.path.exists(model_path):
            with open(model_path, 'rb') as model_file:
                self.model = pickle.load(model_file)
                if hasattr(self.model, "predict"):
                    print(f"{GREEN}[INFO]{END} Loaded existing model from {model_path}")
                else:
                    print(f"{RED}[ERROR]{END} Existing model at {model_path} is not valid. Training a new model.")
                    self.train_new_model()
        else:
            print(f"{RED}[ERROR]{END} No trained model found for domain: {args.domain}")
            self.train_new_model()

    def train_new_model(self):
        logging.info("Training a new model...")
        X, y = self.generate_training_data()
        if not self.validate_training_data(X, y):
            return
        try:
            self.model.train(X, y)
            self.save_model()
        except Exception as e:
            logging.error(f"Error training the model: {e}")

    def save_model(self):
        model_path = f"{normalize_domain(args.domain)}_xss_model.pkl"
        try:
            with open(model_path, 'wb') as model_file:
                pickle.dump(self.model, model_file)
            logging.info(f"Model saved to {model_path}")
        except Exception as e:
            logging.error(f"Error saving the model: {e}")

    def generate_training_data(self):
        X = []
        y = []
        if not self.scan_results:
            logging.error("No scan results available to generate training data.")
            return X, y
        for result in self.scan_results:
            features = self.extract_features(result['query_params'])
            X.append(features)
            y.append(result['success'])
        return X, y

    def validate_training_data(self, X, y):
        if not X or not y:
            logging.error("Training data is empty. Cannot train the model.")
            return False
        return True

    def auto_filter(self, urls):
        filtered_urls = []
        for url in urls:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            features = self.extract_features(query_params)
            if self.model.predict([features])[0]:
                filtered_urls.append(url)
        return filtered_urls

    def extract_features(self, query_params):
        features = [len(query_params)]
        if query_params:
            first_param = list(query_params.keys())[0]
            features.append(len(first_param))
        else:
            features.append(0)
        return features

    def detect_server(self, url):
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = requests.head(url, headers=headers, timeout=10)
            server_header = response.headers.get('Server', '').lower()
            if 'nginx' in server_header:
                return 'nginx'
            elif 'apache' in server_header:
                return 'apache'
            elif 'iis' in server_header:
                return 'iis'
            else:
                return 'generic'  # Default to 'generic' if server type is unknown
        except requests.RequestException as e:
            print(f"{RED}[ERROR]{END} Failed to detect server for {url}: {str(e)}")
            return 'generic'  # Default to 'generic' if there's an error

    def determine_xss_type(self, url, param, payload, response):
        response_text = response.text.lower()
        if "<script>" in response_text or "alert(" in response_text:
            if payload in response_text:
                return "Reflected XSS"
        return "Unknown XSS"

    def scan_urls_for_xss(self, url):
        server_type = self.detect_server(url)
        self.payloads = generate_payloads(server_type)
        if not self.payloads:
            print(f"{RED}[ERROR]{END} No payloads generated for testing.")
            return

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        headers = {'User-Agent': random.choice(USER_AGENTS)}

        for param, values in query_params.items():
            for payload in self.payloads:
                for method in self.methods:
                    try:
                        start_time = time.time()
                        if method in ["GET", "HEAD"]:
                            response = requests.request(method, f"{url}?{param}={payload}", headers=headers, verify=False, timeout=10)
                        else:
                            response = requests.request(method, url, data={param: payload}, headers=headers, verify=False, timeout=10)
                        response_time = time.time() - start_time
                        success = response.status_code == 200 and payload in response.text

                        logging.info(f"Testing {url} with payload {payload} using method {method}. Success: {success}")

                        self.scan_results.append({'query_params': query_params, 'success': int(success)})

                        if success:
                            xss_type = self.determine_xss_type(url, param, payload, response)
                            self.vulnerable_urls.append((url, payload, method))
                            insert_vulnerability_data(url, payload, method, xss_type, int(success))
                            with open('audit_links.txt', 'a') as file:
                                file.write(f"{url},{payload},{method},{xss_type}\n")
                        else:
                            logging.info(f"No XSS vulnerability detected for {url} with payload {payload} using method {method}")

                        self.rl_agent.learn(url, param, payload, method, success)

                        # Insert training data
                        insert_training_data(url, param, payload, server_type, method, response.status_code, response_time, response.text, int(success), response.text[:100], int(success))

                    except requests.RequestException as e:
                        logging.error(f"Failed to test {url} with {method}: {str(e)}")

    def start_scan(self):
        if self.use_model and self.model:
            print(f"{GREEN}[INFO]{END} Using trained model to filter URLs before scanning.")
            self.url_list = self.auto_filter(self.url_list)

        with ThreadPoolExecutor(max_workers=self.thread_number) as executor:
            future_to_url = {executor.submit(self.scan_urls_for_xss, url): url for url in self.url_list}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"{RED}[ERROR]{END} {url} generated an exception: {exc}")

        if self.report_file:
            with open(self.report_file, 'w') as f:
                f.write(f"Total URLs scanned: {len(self.url_list)}\n")
                f.write(f"Total Confirmed Cross Site Scripting Vulnerabilities: {len(self.vulnerable_urls)}\n")
                for url, payload, method in self.vulnerable_urls:
                    f.write(f"Vulnerable URL: {url} with Payload: {payload} using Method: {method}\n")

        return self.vulnerable_urls

    def check_blind_xss(self):
        if not self.blind_xss_endpoint:
            return

        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = requests.get(self.blind_xss_endpoint, headers=headers, timeout=10)
            if response.status_code == 200:
                print(f"{GREEN}[INFO]{END} Blind XSS endpoint check successful. Response: {response.text}")
            else:
                print(f"{RED}[ERROR]{END} Blind XSS endpoint check failed. Status code: {response.status_code}")
        except requests.RequestException as e:
            print(f"{RED}[ERROR]{END} Failed to check Blind XSS endpoint: {str(e)}")

def terminate_scan():
    global stop_animation
    stop_animation = True
    print(f"\n{RED}[INFO]{END} Scan terminated by user or due to time limit.")
    db_queue.put((None, "terminate", None))
    db_thread.join()
    db_connection.close()  # Ensure the database connection is closed
    sys.exit(0)

# Handle Ctrl+C gracefully
signal.signal(signal.SIGINT, lambda signal, frame: terminate_scan())

if __name__ == '__main__':
    args = get_arguments()
    
    if args.extractquick:
        if args.domain:
            fetch_and_clean_urls(args.domain, stream_output=True)
        else:
            print(f"{RED}[ERROR]{END} Please provide a target domain for --extractquick.")
        stop_animation = True
        sys.exit(1)

    if args.list:
        target_urls = read_target_from_file(args.list)
    elif args.domain:
        target_urls = [args.domain]
        if args.deepcrawl:
            commoncrawl_urls = fetch_urls_commoncrawl(args.domain)
            wayback_urls = fetch_urls_wayback(args.domain)
            target_urls.extend(commoncrawl_urls)
            target_urls.extend(wayback_urls)
        elif args.crawl:
            crawled_urls = crawl_website(args.domain)
            target_urls.extend(crawled_urls)
        target_urls = list(set(target_urls))
        with open('found_links.txt', 'w') as file:
            file.write("\n".join(target_urls))
        print(f"{GREEN}[INFO]{END} Total URLs found: {len(target_urls)}")
    else:
        print(f"{RED}[ERROR]{END} Please provide either a URLs list file or a target domain.")
        stop_animation = True
        sys.exit(1)

    if args.duration:
        timer = threading.Timer(args.duration, terminate_scan)
        timer.start()

    scanner = XSSScanner(target_urls, args.thread, args.report, args.mode, args.blind_xss_endpoint, args.use_model)
    vulnerable_urls = scanner.start_scan()

    # Train the model after scanning
    if scanner.scan_results:
        scanner.train_new_model()
    logging.info(f"Scan completed. Total URLs scanned: {len(target_urls)}. Check {args.report} for details.")

    print(f"{GREEN}[INFO]{END} Scan completed. Total URLs scanned: {len(target_urls)}. Check {args.report} for details.")

    total_links_audited = len(target_urls)
    with open('total_links_audited.txt', 'w') as file:
        file.write(str(total_links_audited))  # Write the total number of links audited to a text file
    logging.info(f"Total Links Audited: {total_links_audited}")

    print(f"[{current_time}] Total Links Audited: ", total_links_audited)

    for url, payload, method in vulnerable_urls:
        print(f"Vulnerable URL: {url} with Payload: {payload} using Method: {method}")
    print(f"[{current_time}] Total Confirmed Cross Site Scripting Vulnerabilities: ", len(vulnerable_urls))
    logging.info(f"Total Confirmed Cross Site Scripting Vulnerabilities: {len(vulnerable_urls)}")

    # Stop the cursor animation
    stop_animation = True

    # Ensure to close the database connection
    db_connection.close()

    # Check for Blind XSS results
    scanner.check_blind_xss()
    
# Function to view data in the database
def view_db():
    connection = sqlite3.connect('xss_scan_results.db')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM vulnerabilities")
    rows = cursor.fetchall()
    for row in rows:
        print(row)
    connection.close()

# Function to view trained model data
def view_trained_data():
    model_path = f"{normalize_domain(args.domain)}_xss_model.pkl"
    if os.path.exists(model_path):
        with open(model_path, 'rb') as model_file:
            model = pickle.load(model_file)
            print(model)
    else:
        print(f"{RED}[ERROR]{END} No trained model found for domain: {args.domain}")

# Call these functions as needed
# view_db()
# view_trained_data()
