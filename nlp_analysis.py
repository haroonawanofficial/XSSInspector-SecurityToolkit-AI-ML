import requests
from bs4 import BeautifulSoup

def analyze_content(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                inputs = form.find_all('input')
                for input_tag in inputs:
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type')
                    if input_type in ['text', 'email', 'search', 'password', 'url']:
                        print(f"Form action: {action}, Input name: {input_name}, Input type: {input_type}")
            return forms
    except requests.RequestException as e:
        print(f"Failed to analyze content for {url}: {str(e)}")
        return []
