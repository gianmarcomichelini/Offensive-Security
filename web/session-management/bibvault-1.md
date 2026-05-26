## Bibvault 1 - JWT Signature Not Verified

### Transitioning to Client-Side Signed Sessions

Moving toward modern architectures, we encounter **JSON Web Tokens (JWT)**, which are designed to store session data on the client while preventing tampering through a cryptographic signature. A JWT is composed of three distinct, Base64url-encoded segments: the **header**, the **payload**, and the **signature**.

- **Header**: Defines the token type and the signing algorithm used.
    
- **Payload**: Contains the actual session "claims," such as user IDs or roles.
    
- **Signature**: A hash generated using the header, payload, and a secret key known only to the server.
    

### The Signature Verification Failure & Source Code Analysis

The "Bibvault 1" challenge exposes a critical implementation flaw where the server decodes the token to read the claims but completely omits the verification of the signature.

By analyzing the application's backend code, the specific vulnerability is located within the `authenticateToken` middleware. The developer utilized `jwt.decode(token)` rather than the secure `jwt.verify(token, JWT_SECRET)`. Because `decode` merely translates the Base64 strings without verifying the cryptographic hash, the server blindly trusts any data supplied by the client. This vulnerability highlights that a JWT is only as secure as the server's verification logic; an unverified token is effectively no more secure than a simple Base64-encoded cookie.

### Exploitation Workflow and IDOR Pivot

While the initial assumption might be to exploit the application's file-fetching SSRF utility, the source code reveals a strict filter blocking the administrative user (`gabibbo`) from using that endpoint. Instead, the lack of signature verification must be used to trigger an **Insecure Direct Object Reference (IDOR)** on the file listing endpoint.

1. **Reconnaissance**: After registering and authenticating with a standard account, the attacker captures the assigned JWT and decodes it using tools like **jwt.io** or the **Burp JWT Editor** extension.
    
2. **Payload Tampering**: The attacker modifies the decoded JSON payload to match the application's administrative identity. The `"username"` claim is changed from the standard user to `"gabibbo"`.
    
3. **Re-encoding**: The attacker re-encodes the tampered payload segment back into strict Base64url format, ensuring no invalid padding characters (like `%3d` or `=`) are introduced.
    
4. **IDOR Exploitation**: The modified token is sent back to the server via a `GET /files` request. Because the server does not validate the third segment (the signature), it accepts the `"gabibbo"` identity as legitimate. The server's logic dynamically routes the user to Gabibbo's private server directory without further authorization checks.
    
5. **Flag Retrieval**: The server returns the HTML interface displaying the administrator's private files. The attacker notes the unique UUID filename of the hidden file and executes a subsequent `GET /download/?fileName=[UUID]` request using the same forged token to extract the plaintext flag.

