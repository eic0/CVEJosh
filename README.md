# CVEJosh

Python Script to check daily for updated CVEs in the last 24 hours and if a vendor is mentioned check shodan for hosts running it.
Additionally it'll also send you a telegram message if you prodive a telegram bot token and chat id

## Requirements:
- pip install -r requirements.txt
- .env file with:
    - shodan API key
    - opencve account or host it yourself (https://github.com/opencve/opencve)
    - telegram bot token and chat id (use: https://api.telegram.org/bot$bottoken$/getUpdates to retrieve your chatid)
----------

## Usage:
- python main.py
    - It'll run and update daily. 

## Docker:
- docker build -t cvejoshcon .
- docker run -d --name CVEJosh --env-file .env cvejoshcon