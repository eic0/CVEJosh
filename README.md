Python Script to check for updated CVEs daily and if a vendor is mentioned check shodan for hosts running it.
Additionally it'll also send you a telegram message if you prodive a telegram bot token and chat id


Requirements:
- pip install requests shodan python-dotenv
- shodan API key
- opencve account or host it yourself (https://github.com/opencve/opencve)
- telegram bot token and chat id
- .env file with this format:
OPEN_CVE_USERNAME=
OPEN_CVE_PASSWORD=
SHODAN_API_KEY=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

Usage:
- just run python main.py daily for best results