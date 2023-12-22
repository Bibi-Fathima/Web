# pip install numpy scikit-learn flask 
# pip install pipreqs

from flask import Flask, render_template, request
import numpy as np
import pickle
import re
from urllib.parse import urlparse
import whois
import requests
import datetime
from requests.exceptions import SSLError




app = Flask(__name__)

with open('Phishing_Website.pkl', 'rb') as f:
    model = pickle.load(f)



def have_ip(url):
    # Regular expression for matching IP addresses
    ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    return bool(re.search(ip_regex, url))

def have_at(url):
    return '@' in url

def url_length(url):
    return len(url)

def url_depth(url):
    # Counting the number of slashes in the path of the URL
    return url.count('/')

def redirection(url):
    try:
        # You might need to make an HTTP request and check the response headers
        response = requests.head(url)
        return response.is_redirect
    except SSLError as e:
        print("SSL Certificate Error:", e)
        return False

def https_domain(url):
    return urlparse(url).scheme == 'https'



@app.route('/', methods=['GET','POST'])
def home():
    if request.method=='POST':
        url = request.form['url']

        if have_ip(url)==False:
            have_ips=0
        else:
            have_ips=1
        if have_at(url)==False:
            have_ats=0
        else:
            have_ats=1
        if redirection(url)==False:
            redirections=0
        else:
            redirections=1
        if https_domain(url)==False:
            https_domains=0
        else:
            https_domains=1
        features = [have_ips,have_ats,url_length(url),url_depth(url),redirections,https_domains]
        input_data = np.array([features])

        predictions = model.predict(input_data)[0]
        if predictions==0:
            prediction = f'Phishing Website-->  {prediction}'
        else:
            prediction = f'Genuine Website-->  {prediction}'

        return render_template('index.html', prediction=prediction)
    return render_template('index.html')
    


@app.route('/module', methods=['GET','POST'])
def index():
  # Example usage:
  if request.method=='POST':
    url = request.form['url']
    print("Have_IP:", have_ip(url))
    print("Have_At:", have_at(url))
    print("URL_Length:", url_length(url))
    print("URL_Depth:", url_depth(url))
    print("Redirection:", redirection(url))
    print("https_Domain:", https_domain(url))

    try:
        # For Domain_Age and Domain_End, you might use a library like python-whois
        domain_info = whois.whois(urlparse(url).hostname)

        # Access the datetime objects directly and calculate the age and remaining time
        creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
        expiration_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date

        # Check if the dates are not None (some domains may not have creation or expiration dates)
        if creation_date and expiration_date:
            domain_age = (expiration_date - creation_date).days
            domain_end = (expiration_date - datetime.datetime.now()).days
            print("Domain_Age:", domain_age)
            print("Domain_End:", domain_end)
            prediction = "Genuine Website"
        else:
            print("Unable to retrieve creation or expiration date for the domain.")
            prediction="Phishing Website"
    except whois.parser.PywhoisError as e:
          prediction = "Unable to retrieve"
    return render_template('index.html',prediction=prediction)
  return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)