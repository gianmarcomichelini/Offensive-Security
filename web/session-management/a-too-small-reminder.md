## A TOO small reminder... - Session ID Brute-Forcing

> x Exam (19)

### Application Architecture and Reconnaissance

Moving to the second practical scenario, one encounters the challenge titled "A TOO small reminder...", which focuses on exploiting weak session identifiers. This application is structured around a JSON based Application Programming Interface that exposes five distinct endpoints, which include the root directory serving as a descriptive index, alongside endpoints for registration, login, logout, and a restricted administrative panel. The primary objective of this exercise requires registering a standard user account, authenticating to receive a session token, and subsequently observing the token's structural characteristics to successfully hijack the active administrative session. This laboratory is sourced from the OliCyber Training platform, specifically referenced at [https://training.olicyber.it/challenges#challenge-36](https://www.google.com/search?q=https://training.olicyber.it/challenges%23challenge-36).

Upon authenticating with the newly created credentials, the attacker must utilize an intercepting proxy like Burp Suite to meticulously inspect the HTTP response headers, focusing specifically on the `Set-Cookie` directive issued by the server. The initial reconnaissance phase involves logging out and logging back in multiple times, or registering several distinct accounts, to gather a sample set of session identifiers. By comparing these collected values, the attacker can rapidly deduce the total size of the session identifier space and assess whether it is realistically feasible to systematically guess every possible value.

### Entropy and Predictable Identifiers

The fundamental vulnerability exposed in this laboratory exercise relates to insufficient cryptographic entropy.

> **Cryptographic Entropy**: A measure of the unpredictability and randomness inherent in a generated value, where higher entropy significantly increases the computational difficulty of successfully guessing or brute forcing that value.

A secure session identifier must always be generated utilizing a cryptographically secure pseudo random number generator, and it must contain enough inherent randomness to make guessing mathematically infeasible. The Open Worldwide Application Security Project rigorously recommends a minimum of 128 bits of entropy for session identifiers. If an application utilizes sequential integers or an excessively small identifier space, such as numbers falling below 10000, the identifier effectively possesses fewer than 14 bits of entropy. This lack of complexity renders the session management mechanism trivially brute forceable, allowing an attacker to simply iterate through all numerical possibilities until they inadvertently assume the identity of another active user, including the administrator.

### Executing the Brute-Force Attack

To successfully exploit this mathematical weakness, the attacker must first establish a behavioral baseline for the application's authorization logic. This is achieved by sending a standard `GET` request to the `/admin` endpoint under three distinct conditions, which include using a valid standard user session cookie, omitting the cookie entirely, and supplying a deliberately fabricated, non existent cookie value. By carefully comparing the HTTP status codes, response headers, and response body lengths across these three scenarios, the attacker can identify the specific, observable anomaly that indicates a successfully authorized administrative request.

Once the signature of a successful administrative response is identified, the attacker proceeds to automate the enumeration of the entire session identifier space. This enumeration can be executed seamlessly utilizing Burp Suite Intruder by navigating to the Positions tab to mark only the cookie value as the injection payload, and then deploying a Numbers payload in the Payloads tab that steps through the identified range with a step of 1. Alternatively, an attacker might author a custom automation script leveraging frameworks such as Python alongside the `requests` library to iterate through the identifiers, programmatically filtering the output to print only the responses that deviate from the established standard user baseline. Upon discovering the correct administrative identifier through either method, the attacker simply adopts that cookie value to access the panel and retrieve the flag, demonstrating a complete session hijack resulting from a purely logical and mathematical oversight.


### Technical Workflow: Session Hijacking via Predictable Identifiers

The following sequence details the systematic exploitation of the session management mechanism within the "A TOO small reminder..." challenge, where the lack of cryptographic entropy allows for a successful brute-force attack.

#### Baseline Reconnaissance and Session Acquisition

The initial phase requires establishing a legitimate identity to observe how the application handles session issuance. By interacting with the **JSON API**, an account is registered via the `/register` endpoint and authenticated through `/login`. Upon successful authentication, the server issues a `Set-Cookie` header containing a `session_id`. In this specific environment, the identifier is assigned as a simple sequential integer (e.g., `session_id=262`), revealing that the session management logic utilizes a predictable state iteration rather than a **Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)**.

#### Authorization Logic Probing

To identify the criteria for a successful hijack, the `/admin` endpoint is probed under varying conditions.

- **Unauthenticated/Invalid Request**: Sending a request with an arbitrary or missing `session_id` yields an `HTTP 403 Forbidden` response with a consistent body length (e.g., 56 bytes).
    
- **Authenticated (Low Privilege)**: Sending the request with the user's valid session ID also results in a `403 Forbidden`, as the application correctly identifies the user but denies access to administrative resources. This consistency establishes a **behavioral baseline**, where any response deviating from a `403` status or the specific 56-byte length indicates a successful authorization bypass.
    

#### Automated Enumeration via Burp Intruder

The exploitation is automated using the **Burp Suite Intruder** tool to traverse the small session ID space.

- **Payload Positioning**: The `GET /admin` request is captured, and the numerical value of the `session_id` is marked as the single injection point (e.g., `session_id=§262§`).
    
- **Payload Configuration**: A **Numbers payload** is configured to iterate sequentially from `1` to an upper bound (such as `500` or `10000`), utilizing a step increment of `1`.
    
- **Attack Execution**: The attack systematically replaces the cookie value in each outbound request. By sorting the results by **Status Code** or **Response Length**, a singular anomaly is identified—typically an `HTTP 200 OK`.
    

#### Privilege Escalation and Flag Retrieval

The anomalous `session_id` corresponds to the active session of the administrator. By adopting this specific integer value into the browser's cookie storage or replaying the request in **Burp Repeater**, the attacker gains full access to the administrative panel. The server, inherently trusting the client-supplied identifier without further verification of the underlying session owner, serves the restricted administrative content, including the target flag.

