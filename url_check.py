import requests
import time
import sys
import os

# --- Configuration ---
API_KEY = " " #paste your API Key here ‼️
API_URL = "https://www.virustotal.com/api/v3"


# --- Banner Function ---
def banner():
    os.system('clear' if os.name == 'posix' else 'cls')  # Clear screen

    # ASCII Art Banner for "URL Check"
    print(r"""
  _    _ _____  _         _____ _               _    
 | |  | |  __ \| |       / ____| |             | |   
 | |  | | |__) | |      | |    | |__   ___  ___| | __
 | |  | |  _  /| |      | |    | '_ \ / _ \/ __| |/ /
 | |__| | | \ \| |____  | |____| | | |  __/ (__|   < 
  \____/|_|  \_\______|  \_____|_| |_|\___|\___|_|\_\

    """)

    # Color codes
    RED = '\033[1;31m'
    YELLOW = '\033[1;93m'
    GREEN = '\033[1;92m'
    GRAY = '\033[1;90m'
    RESET = '\033[0m'

    # Tool Info
    print(f'{RED}       ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀{RESET}')
    print(f"{YELLOW}      URL Check Ver 0.1 - by Fazal {RESET}")
    print(f"{GRAY} URL Check is a simple and light tool for information gathering and malicious URL analysis.{RESET}")
    print()


# --- Functions ---
def loading_spinner(duration=15):
    spinner = ['|', '/', '-', '\\']
    end_time = time.time() + duration
    while time.time() < end_time:
        for symbol in spinner:
            sys.stdout.write(f'\rWaiting for analysis to complete... {symbol}')
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\rAnalysis completed!          \n')


def submit_url(url):
    response = requests.post(
        f"{API_URL}/urls",
        headers={"x-apikey": API_KEY},
        data={"url": url}
    )
    if response.status_code != 200:
        raise Exception(f"Error submitting URL: {response.text}")
    return response.json()["data"]["id"]


def get_analysis(url_id):
    response = requests.get(
        f"{API_URL}/analyses/{url_id}",
        headers={"x-apikey": API_KEY}
    )
    if response.status_code != 200:
        raise Exception(f"Error fetching analysis: {response.text}")
    return response.json()["data"]


def display_summary(url, stats):
    print("\n--- URL Analysis Summary ---")
    print(f"Submitted URL: {url}")
    print("Detection Stats:")
    print(f" - Harmless:   {stats.get('harmless', 0)}")
    print(f" - Malicious:  {stats.get('malicious', 0)}")
    print(f" - Suspicious: {stats.get('suspicious', 0)}")
    print(f" - Undetected: {stats.get('undetected', 0)}")
    print(f" - Timeout:    {stats.get('timeout', 0)}")


def display_engine_results(results):
    print("\n--- Engine-wise Detection Results ---")
    for engine, result in results.items():
        category = result.get("category", "N/A")
        engine_result = result.get("result", "N/A")
        method = result.get("method", "N/A")
        print(f"\n[Engine: {engine}]")
        print(f"  - Category: {category}")
        print(f"  - Result:   {engine_result}")
        print(f"  - Method:   {method}")


def run():
    try:
        banner()
        url = input("Enter your URL: ").strip()
        url_id = submit_url(url)
        loading_spinner(duration=15)
        analysis_data = get_analysis(url_id)
        attributes = analysis_data.get("attributes", {})
        stats = attributes.get("stats", {})
        results = attributes.get("results", {})

        display_summary(url, stats)
        more_result = int(input("Do you need Search Engine data (1 for Yes, 0 for No): "))
        if more_result == 1:
            display_engine_results(results)
        else:
            run()

    except Exception as e:
        print(f"[Error] {e}")


def main():
    if API_KEY.strip() == "":
        print("🔐 Set a new API key to continue.")
        print("📄 For help, check the setup instructions in the 'setup_API.txt' file.")

    else:
        run()


# --- Entry Point ---
if __name__ == "__main__":
    main()
