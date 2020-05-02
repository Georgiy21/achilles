#!/usr/bin/env python

# url: https://social-engineering.geogiy21.repl.co/

import argparse 
import validators
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment
import yaml

parser = argparse.ArgumentParser(description='The Achilles HTML Vulnerabilty Analyzer Version 1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help='The URL of the HTML to analyze')
parser.add_argument('--config', help='Path to configuration file')
parser.add_argument('-o', '--output', help='Report file output path')

args = parser.parse_args()

config = {'forms': True, 'comments': True, 'passwords': True}

if(args.config):
    print('Using config file: ' + args.config)
    config_file = open(args.config, 'r')
    config_form_file = yaml.load(config_file)
    if config_form_file:
        config = { **config, **config_form_file}

report = ''
url = args.url

if validators.url(url):
    result_html = requests.get(url).text
    parsed_html = BeautifulSoup(result_html, 'html.parser')

    forms           = parsed_html.find_all('form')
    comments        = parsed_html.find_all(string=lambda text:isinstance(text, Comment))
    password_inputs = parsed_html.find_all('input', {'name' : 'password'})

    if config['forms']:
        for form in forms:
            if form.get('action').find('https') < 0 and urlparse(url).scheme != 'https':
                report += 'Form Issue: Insecure form action ' + form.get('action') + 'found in document\n'
    if config['comments']:
        for comment in comments:
            if comment.find('key: ') > -1:
                report += 'Comment Issue: Key is found in the HTML comment, please remove\n'
    if config['passwords']:
        for password_input in password_inputs:
            if password_input.get('type') != 'password':
                report += 'Input Issue: Plaintext password input is found. Please change to password type input'

else:
    print('Invalid url. Please include full url including scheme')

if report == '':
    report += 'Nice job! Your HTML document is secure!'
else:
    header = 'Vulnerabilities Report is as follows:\n'
    header += '=====================================\n'

    report = header + report
    

print(report)

if(args.output):
    f = open(args.output, 'w')
    f.write(report)
    f.close
    print(['Report saved to: ' + args.output])






