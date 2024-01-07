# CVEJosh

Python Script to check for updated CVEs daily and if a vendor is mentioned check shodan for hosts running it.
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
    - ! It will only give you the CVEs of the current day, so running it early in the morning won't give you much.

## Docker:
- docker build -t cvejosh .
- docker run -d --name CVEJosh --env-file .env cvejosh