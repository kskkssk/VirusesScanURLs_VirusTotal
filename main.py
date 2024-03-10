import os
from virustotal_python import Virustotal, VirustotalError
import pandas as pd
import requests
import time

#Insert your API key: limit 500 URLs for one key
#Create more than one key in case of QuotaExceededError
key = ''
VIRUSTOTAL_API_KEY = key


def download_file(url, download_path):
    headers = {
        "accept": "application/json",
        "x-apikey": key
    }
    try:
        url_split = url.split('/')
        filename = url_split[-3] + url_split[-2]
        filepath = os.path.join(download_path, filename)

        response = requests.get(url, headers=headers)
        response.raise_for_status()

        with open(filepath, 'wb') as file:
            file.write(response.content)

        return filepath, filename

    except requests.exceptions.RequestException as err:
        print(f"Failed to download file from {url}: {err}")
        return None, None


def get_scan_id(file_path):
    try:
        with Virustotal(API_KEY=key) as vtotal:
            response = vtotal.request("files", files={"file": open(file_path, "rb")}, method="POST")
            scan_id = response.data["id"]
            return scan_id

    except VirustotalError as err:
        print(f"Failed to scan file: {err}")
        return None


def scan_file(scan_id):
    try:
        with Virustotal(API_KEY=key) as vtotal:
            response = vtotal.request(f"analyses/{scan_id}")
            stats = response.data['attributes']['stats']
            malicious = stats['malicious']
            total = stats['harmless'] + stats['undetected'] + malicious
            print(total)
            if total > 0:
                result = "{}/{}".format(malicious, total)
                return result
            else:
                print('Analysis in progress. Waiting...')
    except VirustotalError as err:
        print(f"Failed to get file report: {err}")
        return "error"


#Insert the path to .xslx table
xls_path = ""
#Insert the name of sheet_list of .xslxtable
sheet_name = ""
#Insert the path to folder for downloading HTML files
download_path = ""
df = pd.read_excel(xls_path, sheet_name)

seconds_per_request = 15
results = []

while True:
    temp_results = []
    #Insert the name of your column with URLs instead of 'URL'
    for url in df['URL']:
        file_path, filename = download_file(url, download_path)
        if file_path:
            scan_id = get_scan_id(file_path)
            if scan_id:
                res = scan_file(scan_id)
                temp_results.append(res)

    if all(result is not None for result in temp_results):
        results.extend(temp_results)
        break

    print("Analysis in progress. Waiting...")
    time.sleep(seconds_per_request)

print(results)
print(len(results))

df['VS'] = results
df.reset_index(drop=True, inplace=True)
df.to_excel(xls_path, engine='openpyxl', sheet_name=sheet_name, index=False)
