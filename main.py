import requests
from datetime import datetime
import shodan
import os
from dotenv import load_dotenv
import time

load_dotenv()

username = os.getenv("OPEN_CVE_USERNAME")
password = os.getenv("OPEN_CVE_PASSWORD")
shodan_api_key = os.getenv("SHODAN_API_KEY")
telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
chat_id = os.getenv("TELEGRAM_CHAT_ID")

# OpenCVE API base url .. replace if hosting own opencve instance
base_url = "https://www.opencve.io/api/cve"

# include shodan key in API
shodan_api = shodan.Shodan(shodan_api_key)

# today's date
today = datetime.now().strftime("%Y-%m-%d")

def get_updated_cves():
    # send get request to get all CVEs
    response = requests.get(base_url, auth=(username, password))
    if response.status_code != 200:
        print("Error with request:", response.status_code)
        return []

    # filter cves only today
    all_cves = response.json()
    updated_cves = [cve for cve in all_cves if cve['updated_at'].startswith(today)]

    return updated_cves

def get_detailed_cve_info(cve_id):
    # send get request to get detailed information about a CVE
    detailed_response = requests.get(f"{base_url}/{cve_id}", auth=(username, password))
    if detailed_response.status_code != 200:
        print(f"Fehler bei der Anfrage für CVE {cve_id}:", detailed_response.status_code)
        return None

    return detailed_response.json()

def search_shodan(vendor, product):
    try:
        # Suchanfrage für Shodan
        results = shodan_api.search(f"{vendor} {product}")
        print(f"Count of found hosts for {vendor} {product}: {results['total']}")
        for result in results['matches']:
            print(f"{result['ip_str']}:{result['port']} {result['hostnames']} - OS: {result['os']} - {result['timestamp'][:10]} ")
            #print(result['data'])
            #print('')
        return results
    except shodan.APIError as e:
        print(f"Error with Shodan-Search: {e}")
        return None

def send_telegram_message(cve_info, shodan_results):
    message = f"<b>CVE ID:</b> {cve_info['id']}\n"
    message += f"<b>Vendor/Product:</b> {cve_info['vendor']}/{cve_info['product']}\n"
    message += f"<b>Summary:</b> {cve_info['summary']}\n"
    if shodan_results and shodan_results['total'] > 0:
        message += "<b>Shodan-Results:</b>\n"
        message += f"<b>Total:</b> {shodan_results['total']}\n"
        for result in shodan_results['matches'][:10]:  # Limit to 10 matches
            message += f"- {result['ip_str']}:{result['port']} {result['hostnames']} - OS: {result['os']} - {result['timestamp'][:10]}\n"

    send_text = 'https://api.telegram.org/bot' + telegram_bot_token + '/sendMessage?chat_id=' + chat_id + '&parse_mode=HTML&text=' + message
    requests.get(send_text)

def main():
    while True:
        updated_cves = get_updated_cves()

        cve_info = {}

        for cve in updated_cves:
            cve_details = get_detailed_cve_info(cve['id'])
            if 'vendors' in cve_details and cve_details['vendors']:
                for vendor, products in cve_details['vendors'].items():
                    products_str = ", ".join(products)  # convert list to string
                    cve_info["id"] = cve_details['id']
                    cve_info["vendor"] = vendor
                    cve_info["product"] = products_str
                    cve_info["summary"] = cve_details['summary']
                    print(f"CVE ID: {cve_info['id']}, Vendor: {cve_info['vendor']}, Products: {cve_info['product']}, Summary: {cve_info['summary']}")
                    # search in shodan
                    for product in products:
                        shodan_results = search_shodan(vendor, product)
                        send_telegram_message(cve_info, shodan_results)
            else:
                print(f"CVE ID: {cve_details['id']}, Summary: {cve_details['summary']}")
                send_telegram_message(cve_details, None)
        time.sleep(86400)

if __name__ == "__main__":
    main()