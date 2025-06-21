import os
import requests
import time

virus_total_api_scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
virus_total_api_report_url = 'https://www.virustotal.com/vtapi/v2/file/report'

virus_toatl_api_key = "5aed02f931a27acfd76cec00df0c2a12f46397b5759576531a237516bcbfc34f"


def scan_file(file_path):
    print("Scanning: ", file_path)
    response = send_scan_request(file_path)
    is_virus = get_report(scan_id=response['scan_id'])
    if is_virus:
        print("VIRUS DETECTED!!! Filepath: ", file_path)
    else:
        print("{} is not virus".format(file_path))


def send_scan_request(file_path):
    params = {'apikey': virus_toatl_api_key}

    file_content = open(file_path, 'rb')
    filename = os.path.basename(file_path)
    files = {'file': (filename, file_content)}

    response = requests.post(virus_total_api_scan_url, files=files, params=params)
    return response.json()

def get_report(scan_id):
    params = {'apikey': virus_toatl_api_key, 'resource': scan_id}
    response = requests.get(virus_total_api_report_url, params=params)
    if not response:
        raise Exception("Unexpected Error in response")
    
    if response.status_code == 200:
        result = response.json()
        if result["verbose_msg"] == "Your resource is queued for analysis":
            print("Waiting for file to be analyzed...")
            time.sleep(5)
            get_report(scan_id)
            return False
        else:
            return result["positives"] > 0
    else:
        print("Received unexpected response with status code:", response.status_code)
        return False


def iterate_files(folder_path):
    for filename in os.listdir(folder_path):
        full_path = os.path.join(folder_path, filename)

        if os.path.isdir(full_path) == True:
            iterate_files(full_path)
        else:
            scan_file(full_path)
            
        


iterate_files(folder_path=r"Your file")
