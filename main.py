import requests
from datetime import datetime, timedelta
import shodan
import os
from dotenv import load_dotenv
import time
import logging
from logging.handlers import RotatingFileHandler

# configure logging
logFormatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
logger = logging.getLogger("CVEJoshLogger")
logger.setLevel(logging.INFO)

load_dotenv()

username = os.getenv("OPEN_CVE_USERNAME")
password = os.getenv("OPEN_CVE_PASSWORD")
shodan_api_key = os.getenv("SHODAN_API_KEY")
telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
chat_id = os.getenv("TELEGRAM_CHAT_ID")

# check if telegram is configured
use_telegram = telegram_bot_token is not None and chat_id is not None

# shodan upgraded api for vuln tag?
upgraded_shodan = False

# send daily cve summary?
send_cve_summary = True

# OpenCVE API base url .. replace if hosting own opencve instance
base_url = "https://www.opencve.io/api/cve"

# include shodan key in API
shodan_api = shodan.Shodan(shodan_api_key)

# get last 24 hours
time_limit = datetime.now() - timedelta(days=1)

def get_updated_cves():
    # send get request to get all CVEs
    response = requests.get(base_url, auth=(username, password))
    if response.status_code != 200:
        logger.warning("Error with request:", response.status_code)
        return []

    # filter cves from last 24 hours
    all_cves = response.json()
    updated_cves = []

    for cve in all_cves:
        updated_at = datetime.strptime(cve['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
        if updated_at > time_limit:
            updated_cves.append(cve)

    return updated_cves

def get_detailed_cve_info(cve_id):
    # send get request to get detailed information about a CVE
    detailed_response = requests.get(f"{base_url}/{cve_id}", auth=(username, password))
    if detailed_response.status_code != 200:
        logger.warning(f"Fehler bei der Anfrage für CVE {cve_id}:", detailed_response.status_code)
        return None

    return detailed_response.json()

def search_shodan(search_string):
    try:
        # search for vendor and product
        results = shodan_api.search(f"{search_string}")
        logger.info(f"Count of found hosts for {search_string}: {results['total']}")
        for result in results['matches']:
            logger.info(f"{result['ip_str']}:{result['port']} {result['hostnames']} - OS: {result['os']} - {result['timestamp'][:10]} ")
        return results
    except shodan.APIError as e:
        logger.warning(f"Error with Shodan-Search: {e}")
        return {'total':0}

def send_shodan_results(cve_info, shodan_results):
    message = f"<b>CVE ID:</b> {cve_info['id']}\n"
    message += f"<b>Vendor/Product:</b> {cve_info['vendor']}/{cve_info['product']}\n"
    message += f"<b>Summary:</b> {cve_info['summary']}\n"
    if shodan_results and shodan_results['total'] > 0:
        message += "<b>Shodan-Results:</b>\n"
        message += f"<b>Total:</b> {shodan_results['total']}\n"
        for result in shodan_results['matches'][:10]:  # limit to 10 matches
            message += f"- {result['ip_str']}:{result['port']} {result['hostnames']} - OS: {result['os']} - {result['timestamp'][:10]}\n"

    send_telegram_message(message)

def send_telegram_message(message):
    send_text = 'https://api.telegram.org/bot' + telegram_bot_token + '/sendMessage?chat_id=' + chat_id + '&parse_mode=HTML&text=' + message
    response = requests.get(send_text)
    if response.status_code != 200:
        logger.error(f"Error while sending Message: {response}")
    else: 
        logger.info("**Sent message**")

def send_cve_summary(message):
    MAX_LENGTH = 3000
    message_length = len(message)
    
    if message_length <= MAX_LENGTH:
        # Wenn die Nachricht 3000 Zeichen oder weniger hat, sende sie direkt.
        send_telegram_message(message)
    else:
        # Wenn die Nachricht länger als 3000 Zeichen ist, teile sie in Blöcke.
        for start in range(0, message_length, MAX_LENGTH):
            # Erstelle einen Block von maximal 3000 Zeichen.
            message_block = message[start:start + MAX_LENGTH]
            # Sende den Block.
            send_telegram_message(message_block)

def main():

    # define logging and file rotation
    fileHandler = RotatingFileHandler("cvejosh.log", maxBytes=5*1024*1024, backupCount=2)
    fileHandler.setFormatter(logFormatter)
    logger.addHandler(fileHandler)

    # stream handler to log to console
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    logger.addHandler(consoleHandler)

    logger.info("**Started**")
    while True:
        updated_cves = get_updated_cves()
        collected_cves =  ""

        for cve in updated_cves:
            cve_details = get_detailed_cve_info(cve['id'])

            # get all infos for the cve into one dict
            cve_info = {
                "id": cve_details.get('id', ''),
                "vendor": '',
                "product": '',
                "summary": cve_details.get('summary', '')[0:150]
            }

            if 'vendors' in cve_details and cve_details['vendors']: # if vendor/products is given
                for vendor, products in cve_details['vendors'].items():
                    products_str = ", ".join(products)  # convert list to string
                    cve_info["vendor"] = vendor
                    cve_info["product"] = products_str

            logger.info(f"CVE ID: {cve_info['id']}, Vendor: {cve_info['vendor']}, Products: {cve_info['product']}, Summary: {cve_info['summary']}")
            if upgraded_shodan: # if the usage of vuln is possible
                shodan_results = search_shodan("vuln:" +  cve_info["id"])
                if shodan_results['total'] < 1: # if shodan doesn't find anything related to that CVE, check if it can find anything about the vendor/product
                    shodan_results = search_shodan(cve_info['vendor'] + " " + cve_info['product'])
            else:
                shodan_results = search_shodan(cve_info['vendor'] + " " + cve_info['product'])
            if use_telegram and shodan_results['total'] > 0:
                    send_shodan_results(cve_info, shodan_results)
            collected_cves += f"CVE ID: {cve_info['id']},{cve_info['vendor']},{cve_info['product']}\nSummary: {cve_info['summary']}\n-------------------------\n"
        if send_cve_summary:
            send_cve_summary('CVE SUMMARY:\n' + collected_cves)

            
        try:
            time.sleep(86400) # wait 24 hours ... not the best solution, but whatever
        except KeyboardInterrupt:
            logger.info("Stopped")
            break

if __name__ == "__main__":
    main()
