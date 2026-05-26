## Password Changer 3000 - Base64-Encoded Token Manipulation

The challenge is available at:
**https://training.olicyber.it/challenges#challenge-59**

This exercise introduces a more sophisticated variant of the same underlying problem. The application allows a user to change any account's password, with one explicit exception: the admin account is blocked. The challenge is to change the admin's password anyway.

### Mapping the Multi-Step Flow

The first task is to carefully document the **password change flow** in its entirety. Multi-step workflows are a particularly fertile ground for logic vulnerabilities because developers often apply security checks at only one stage of the flow, assuming the earlier stages have already validated everything necessary. An attacker who can re-enter the flow at a later stage, or manipulate state between stages, can bypass checks that were never designed to be circumvented mid-flow.

With Burp Suite intercepting all requests, the student walks through the password change process step by step, noting every request generated, every parameter transmitted, and every response received.

### The Token Parameter

A key element to examine is the **`token` parameter** that appears somewhere in the flow. Tokens in web applications frequently encode structured information, and a common pattern is to use **Base64 encoding** to serialize this data. Base64 is an encoding scheme, not an encryption mechanism, meaning it provides no confidentiality whatsoever. Any Base64-encoded value can be decoded trivially:
```
base64 encoded:  eyJ1c2VyIjogImFsaWNlIn0=
decoded:         {"user": "alice"}
```

If the token encodes the target username, and the server uses this token to determine whose password to change, then decoding the token, modifying its contents to reference `admin`, re-encoding it, and injecting it back into the request may be sufficient to bypass the explicit block on the admin account entirely.

> **Key Takeaway:** A multi-step flow is only as secure as its weakest stage. Security checks applied at step one offer no protection if an attacker can manipulate the data passed into step two. Every stage of a sensitive workflow must independently validate that the operation being requested is authorized for the user performing it.


### Solution Analysis

Looking at the URL in the screenshot:

```
password-changer.challs.olicyber.it/change-password.php?token=YWRtaW4=
```

The token value `YWRtaW4=` is simply the Base64 encoding of the string `admin`:

```sh
echo -n "admin" | base64
# output: YWRtaW4=
```

The student correctly identified that the token parameter in the URL was Base64-encoded, decoded it to understand its structure, replaced the original username with `admin`, re-encoded it, and substituted it back into the URL directly in the browser's address bar. No Burp Suite was even necessary in this case, the exploit was entirely URL-level manipulation.

The server received the request, decoded the token, extracted the username `admin`, and proceeded to execute the password change without performing any additional authorization check. The flag confirms the lesson embedded in its own text:

**CyberChef**, available at **[https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)**, is a browser-based tool developed by GCHQ that allows chaining cryptographic and encoding operations visually, making it ideal for quickly decoding and re-encoding tokens during CTF challenges and penetration tests.