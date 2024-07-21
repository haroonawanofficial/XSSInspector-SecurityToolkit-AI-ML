# XSSInpector Security AI ML 

## Overview

World's first fully itnelligent and life long The XSSInpector Security AI ML is a comprehensive tool designed to detect Refeclted, Stored, Blind (XSS) vulnerabilities in server/apps at RFC design, forms, crawls & advanced AI techniques, including deep learning, natural language processing (NLP), reinforcement learning, and automated payload generation, with accuracy and efficient output. Created and Designed by : Haroon Ahmad Awan

## Contact 
- haroon@cyberzeus.pk
- https://www.cyberzeus.pk

## Features

### HTTP Verbs
- **Fuzz**: Built-in HTTP Known to Unknwn HTTP Verb tempering to check for vulnerabilities
  
### Machine Learning
- **Deep Learning Models**: Utilizes neural networks to predict vulnerabilities based on complex features.
- **Model Training and Prediction**: Trains models on past scan results and uses them to filter and prioritize URLs for scanning.

### Natural Language Processing (NLP)
- **Content Analysis**: Analyzes web page content to identify forms and input fields that could be susceptible to XSS attacks.
- **Form and Input Extraction**: Extracts details of forms and input fields to better target XSS injection points.

### Reinforcement Learning
- **Adaptive Learning**: Learns from each scanning attempt to improve payload selection and application over time.
- **History-Based Adjustments**: Adjusts future payload selection based on the success of past attempts.

### Automated Payload Generation
- **Dynamic Payloads**: Generates sophisticated XSS payloads dynamically based on the structure of the web page.
- **Server-Specific Payloads**: Provides tailored payloads for different server types (e.g., nginx, apache, iis).

### URL Crawling
- **Deep Crawling**: Fetches additional URLs using CommonCrawl and Wayback Machine to ensure comprehensive coverage.
- **Targeted Crawling**: Focuses on URLs likely to be vulnerable based on predictive models.

### Reporting and Logging
- **Database Logging**: Logs all scan results in a SQLite database for easy access and analysis.
- **HTML Reports**: Generates detailed HTML reports summarizing the scan results and vulnerabilities found.

### Multi-Threading
- **Concurrent Scanning**: Utilizes multi-threading to scan multiple URLs simultaneously, improving scanning speed and efficiency.

## Usage

### Basic Scan with Deep Crawl and Model
```sh
python xssscanadv.py -d http://testphp.vulnweb.com -t 100 -o vulnerable_urls.txt --deepcrawl --report report.html --duration 3600 --mode autounderstand --use-model
