# XSSInpector Security AI ML 

## Overview

The world's first fully intelligent and lifelong "The XSSInspector Security AI/ML" is a comprehensive tool designed to detect reflected, stored, and blind (XSS) vulnerabilities in servers/apps at RFC design, forms, crawls, and through advanced AI techniques, including deep learning, natural language processing (NLP), reinforcement learning, and automated payload generation, with accuracy and efficient output. Created and designed by Haroon Ahmad Awan.

## Contact 
- haroon@cyberzeus.pk
- https://www.cyberzeus.pk

## Features

# AI-ML Trained Obfuscation Methods

## Known to Unknown
Includes built-in obfuscation methods to automatically check if we successfully bypassed the firewall. Results are then recorded into trained data, enhancing the detection and accuracy of payloads to identify more vulnerabilities.

## HTTP Verbs

### Fuzz
Built-in HTTP verb tampering to check for vulnerabilities, using known and unknown HTTP verbs.

## Machine Learning

### Deep Learning Models
Utilizes neural networks to predict vulnerabilities based on complex features.

### Model Training and Prediction
Trains models on past scan results and uses them to filter and prioritize URLs for scanning.

## Natural Language Processing (NLP)

### Content Analysis
Analyzes web page content to identify forms and input fields that could be susceptible to XSS attacks.

### Form and Input Extraction
Extracts details of forms and input fields to better target XSS injection points.

## Reinforcement Learning

### Adaptive Learning
Learns from each scanning attempt to improve payload selection and application over time.

### History-Based Adjustments
Adjusts future payload selection based on the success of past attempts.

## Automated Payload Generation

### Dynamic Payloads
Generates sophisticated XSS payloads dynamically based on the structure of the web page.

### Server-Specific Payloads
Provides tailored payloads for different server types (e.g., nginx, apache, IIS).

## URL Crawling

### Deep Crawling
Fetches additional URLs using CommonCrawl and Wayback Machine to ensure comprehensive coverage.

### Targeted Crawling
Focuses on URLs likely to be vulnerable based on predictive models.

## Detection of XSS

### Blind XSS
Detects blind XSS vulnerabilities and can use custom endpoints to detect real-time blind XSS, training the software for more accuracy in future scans. Types include:
- Server-Side Blind XSS
- Client-Side Blind XSS
- HTTP verb tampering based Blind XSS
- Server Parameter Tampering for Blind XSS

### Reflected XSS
Identifies reflected XSS vulnerabilities and their subtypes by analyzing the immediate reflection of payloads. Types include:
- GET-Based Reflected XSS
- POST-Based Reflected XSS
- URL-Based Reflected XSS
- HTTP verb tampering based Reflected XSS
- Server Parameter Tampering for Reflected XSS

### Stored XSS
Detects stored XSS vulnerabilities by inspecting whether payloads are saved and executed later within the web application. Types include:
- Database Stored XSS
- File Stored XSS
- HTML Stored XSS
- HTTP verb tampering based Stored XSS
- Server Parameter Tampering for Stored XSS

## Reporting and Logging

### Database Logging
Logs all scan results in a SQLite database for easy access and analysis.

### HTML Reports
Generates detailed HTML reports summarizing the scan results and vulnerabilities found.

## Multi-Threading

### Concurrent Scanning
Utilizes multi-threading to scan multiple URLs simultaneously, improving scanning speed and efficiency.

## Usage

### Basic Scan with Deep Crawl and Model
```sh
python xssscanadv.py -d http://testphp.vulnweb.com -t 100 --report report.html --deepcrawl --duration 420 -s
python xssscanadv.py -d http://testphp.vulnweb.com -t 100 --report report.html --deepcrawl --duration 420 -s --mode autounderstand --use-model


