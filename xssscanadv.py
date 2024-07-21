import threading
import sys
import requests
import argparse
import sqlite3
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs
import os
import pickle
import queue
import signal
import csv

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from deep_learning import DeepLearningModel
from nlp_analysis import analyze_content
from reinforcement_learning import ReinforcementLearningAgent
from payload_generation import generate_payloads

# Constants for terminal colors
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\033[94m', '\033[91m', '\033[97m', '\033[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

# Setup basic logging
current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
print(f"{GREEN}[INFO]{END} Starting the XSS Scanner at {current_time}.")
requests.packages.urllib3.disable_warnings()

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

# Argument parsing
def get_arguments():
    parser = argparse.ArgumentParser(description='Advanced XSS Reporter')
    parser.add_argument("-t", "--thread", type=int, default=50, help="Number of Threads to Use. Default=50")
    parser.add_argument("-o", "--output", help="Save Vulnerable URLs in TXT file")
    parser.add_argument("-s", "--subs", action='store_true', help="Include Results of Subdomains")
    parser.add_argument("--deepcrawl", action='store_true', help="Uses All Available APIs of CommonCrawl for Crawling URLs [**Takes Time**]")
    parser.add_argument("--report", help="Generate an HTML report", default=None)
    parser.add_argument("--duration", type=int, help="Duration in seconds to run the scan before auto-kill")
    parser.add_argument("--mode", choices=["finetune", "autounderstand"], default="autounderstand", help="Fine-tune manually or auto-understand")
    parser.add_argument("--blind-xss-endpoint", help="Public endpoint to check for Blind XSS payload execution")
    parser.add_argument("--use-model", action='store_true', help="Use the trained model to filter URLs before scanning")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-l", "--list", help="URLs List, e.g., google_urls.txt")
    group.add_argument("-d", "--domain", help="Target Domain Name, e.g., testphp.vulnweb.com")
    return parser.parse_args()

# Function to fetch URLs using CommonCrawl
def fetch_urls_commoncrawl(domain):
    print(f"{GREEN}[INFO]{END} Fetching URLs from CommonCrawl for domain: {domain}")
    cc_api = f"http://index.commoncrawl.org/CC-MAIN-2023-17-index?url={domain}&output=json"
    response = requests.get(cc_api)
    urls = []
    if response.status_code == 200:
        results = response.json()
        for result in results:
            urls.append(result['url'])
    else:
        print(f"{RED}[ERROR]{END} Failed to fetch URLs from CommonCrawl.")
    return urls

# Function to fetch URLs using Wayback Machine
def fetch_urls_wayback(domain):
    print(f"{GREEN}[INFO]{END} Fetching URLs from Wayback Machine for domain: {domain}")
    wayback_api = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    response = requests.get(wayback_api)
    urls = []
    if response.status_code == 200:
        results = response.json()
        urls = [result[0] for result in results]
    else:
        print(f"{RED}[ERROR]{END} Failed to fetch URLs from Wayback Machine.")
    return urls

# Function to save training data to CSV
def save_training_data_to_csv():
    with open('training_data.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['url', 'param', 'payload', 'server_type', 'method', 'response_code', 'response_time', 'response_pattern', 'success', 'content_snippet', 'vulnerable'])
        cursor = db_connection.cursor()
        cursor.execute("SELECT url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable FROM training_data")
        rows = cursor.fetchall()
        for row in rows:
            writer.writerow(row)

# Function to insert training data
def insert_training_data(url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable):
    query = """
        INSERT INTO training_data (url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    db_queue.put((db_connection, query, (url, param, payload, server_type, method, response_code, response_time, response_pattern, success, content_snippet, vulnerable)))

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
        self.payloads = generate_payloads()
        self.methods = ["CAT", "JEFF", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
        self.model = DeepLearningModel() if use_model else None
        self.rl_agent = ReinforcementLearningAgent()

    def load_or_train_model(self):
        model_path = f"{args.domain.replace('http://', '').replace('https://', '').replace('/', '')}_xss_model.pkl"
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
        print(f"{GREEN}[INFO]{END} Training a new model...")
        X, y = self.generate_training_data()
        if not X or not y:
            print(f"{RED}[ERROR]{END} Training data is empty. Cannot train the model.")
            return
        self.model.train(X, y)
        self.save_model()

    def save_model(self):
        model_path = f"{args.domain.replace('http://', '').replace('https://', '').replace('/', '')}_xss_model.pkl"
        with open(model_path, 'wb') as model_file:
            pickle.dump(self.model, model_file)
        print(f"{GREEN}[INFO]{END} Model saved to {model_path}")

    def generate_training_data(self):
        X = []
        y = []
        if not self.scan_results:
            print(f"{RED}[ERROR]{END} No scan results available to generate training data.")
            return X, y
        for result in self.scan_results:
            features = self.extract_features(result['query_params'])
            X.append(features)
            y.append(result['success'])
        return X, y

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
            response = requests.head(url, timeout=10)
            server_header = response.headers.get('Server', '').lower()
            if 'nginx' in server_header:
                return 'nginx'
            elif 'apache' in server_header:
                return 'apache'
            elif 'iis' in server_header:
                return 'iis'
            else:
                return 'unknown'
        except requests.RequestException as e:
            print(f"{RED}[ERROR]{END} Failed to detect server for {url}: {str(e)}")
            return 'unknown'

    def scan_urls_for_xss(self, url):
        server_type = self.detect_server(url)
        payloads = generate_payloads(server_type)
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for param, values in query_params.items():
            for payload in payloads:
                for method in self.methods:
                    try:
                        start_time = time.time()
                        if method == "GET" or method == "HEAD":
                            response = requests.request(method, f"{url}?{param}={payload}", verify=False, timeout=10)
                        else:
                            response = requests.request(method, url, data={param: payload}, verify=False, timeout=10)
                        response_time = time.time() - start_time
                        success = response.status_code == 200 and payload in response.text
                        self.scan_results.append({'query_params': query_params, 'success': int(success)})

                        if success:
                            self.vulnerable_urls.append((url, payload, method))
                            db_queue.put((db_connection, "INSERT INTO vulnerabilities (url, payload, discovered_at, method, success) VALUES (?, ?, ?, ?, ?)",
                                          (url, payload, datetime.now(), method, int(success))))
                        self.rl_agent.learn(url, param, payload, method, success)

                        # Insert training data
                        insert_training_data(url, param, payload, server_type, method, response.status_code, response_time, response.text, int(success), response.text[:100], int(success))

                    except requests.RequestException as e:
                        print(f"{RED}[ERROR]{END} Failed to test {url} with {method}: {str(e)}")

    def start_scan(self):
        if self.use_model and self.model:
            print(f"{GREEN}[INFO]{END} Using trained model to filter URLs before scanning.")
            self.url_list = self.auto_filter(self.url_list)

        with ProcessPoolExecutor() as executor:
            future_to_url = {executor.submit(self.scan_urls_for_xss, url): url for url in self.url_list}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"{RED}[ERROR]{END} {url} generated an exception: {exc}")

        if self.report_file:
            with open(self.report_file, 'w') as f:
                for url, payload, method in self.vulnerable_urls:
                    f.write(f"Vulnerable URL: {url} with Payload: {payload} using Method: {method}\n")

        return self.vulnerable_urls

    def check_blind_xss(self):
        if not self.blind_xss_endpoint:
            return

        try:
            response = requests.get(self.blind_xss_endpoint, timeout=10)
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
    save_training_data_to_csv()
    sys.exit(0)

# Handle Ctrl+C gracefully
signal.signal(signal.SIGINT, lambda signal, frame: terminate_scan())

if __name__ == '__main__':
    args = get_arguments()
    
    if args.list:
        target_urls = read_target_from_file(args.list)
    elif args.domain:
        target_urls = [args.domain]
        if args.deepcrawl:
            target_urls.extend(fetch_urls_commoncrawl(args.domain))
            target_urls.extend(fetch_urls_wayback(args.domain))
        target_urls = list(set(target_urls))
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

    print(f"{GREEN}[INFO]{END} Scan completed. Total URLs scanned: {len(target_urls)}. Check {args.report} for details.")

    total_links_audited = len(target_urls)
    with open('total_links_audited.txt', 'w') as file:
        file.write(str(total_links_audited))  # Write the total number of links audited to a text file

    print(f"{current_time}] Total Links Audited: ", total_links_audited)

    for url, payload, method in vulnerable_urls:
        print(f"Vulnerable URL: {url} with Payload: {payload} using Method: {method}")
    print(f"[{current_time}] Total Confirmed Cross Site Scripting Vulnerabilities: ", len(vulnerable_urls))

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
    model_path = f"{args.domain.replace('http://', '').replace('https://', '').replace('/', '')}_xss_model.pkl"
    if os.path.exists(model_path):
        with open(model_path, 'rb') as model_file:
            model = pickle.load(model_file)
            print(model)
    else:
        print(f"{RED}[ERROR]{END} No trained model found for domain: {args.domain}")

# Call these functions as needed
# view_db()
# view_trained_data()
