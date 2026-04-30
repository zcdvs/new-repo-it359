"""
Machine Learning-Based Fileless Malware Detector
IT 359 Final Project - Fileless Malware Research

This script uses an AI model (via the college's OpenWebUI /api/chat/completions
endpoint) to classify process behavior as benign or potentially malicious.

It builds on the same behavioral ideas as detector.py, but instead of
hard-coded rules, it sends process features to the AI model and
interprets the response.

WARNING: This is for educational purposes only.
Only use in controlled lab environments.
"""

from google import genai

# The client gets the API key from the environment variable `GEMINI_API_KEY`.
client = genai.Client()

response = client.models.generate_content(
    model="gemini-3-flash-preview", contents="Explain how AI works in a few words"
)
print(response.text)


def classify_process_behavior(features: dict) -> str:
    response = client.models.generate_content(
        model="gemini-3-flash-preview", contents=str(features)
    )
    return response.text

def identify_suspicious_processes(processes: list) -> list:
    suspicious_processes = []
    for proc in processes:
        features = {
            "pid": proc["pid"],
            "name": proc["name"],
            "cmdline": proc["cmdline"],
            "user": proc["user"],
            "host": proc["host"]
        }
        result = classify_process_behavior(features)
        if "malicious" in result.lower():
            suspicious_processes.append(proc)
    return suspicious_processes

def main():
    # Example process features
    process_features = {
        "pid": 1234,
        "name": "powershell.exe",
        "cmdline": "-nop -w hidden -enc ...",
        "user": "user1",
        "host": "localhost"
    }

    result = classify_process_behavior(process_features)
    print(f"Process classification result: {result}")

    suspicious_processes = identify_suspicious_processes([process_features])
    print(f"Suspicious processes found: {suspicious_processes}")

    # Take action on suspicious processes (e.g., alert, terminate, etc.)
    for proc in suspicious_processes:
        print(f"Taking action on suspicious process: {proc}")
        # Example action: terminate the process
        # terminate_process(proc["pid"])

        # Log the action taken
        print(f"Terminated suspicious process: {proc}")

    # Log the action taken
    with open("suspicious_processes.log", "a") as log_file:
        log_file.write(f"Terminated suspicious process: {proc}\n")

    if __name__ == "__main__":
        main()