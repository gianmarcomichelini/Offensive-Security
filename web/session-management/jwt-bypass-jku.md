## JWT authentication bypass via jku header injection

The current laboratory exercise focuses on a sophisticated authentication bypass vulnerability that emerges when a web application dynamically retrieves cryptographic materials via the `jku` header parameter but critically omits strict domain validation.

> **External Key Retrieval Exploitation** occurs when an application implicitly trusts an adversary supplied Uniform Resource Locator to fetch a public key, fundamentally shifting the cryptographic root of trust from the internal server configuration to an external infrastructure controlled by the attacker.

### Adversarial Infrastructure Preparation

The practical execution begins by establishing a baseline understanding of the target access controls, where the practitioner authenticates using standard credentials and intercepts the subsequent HTTP GET request directed to the `/my-account` endpoint. By modifying the target path within the Burp Repeater module to the `/admin` endpoint, the practitioner confirms that the administrative interface is heavily restricted and requires elevated privileges.

To orchestrate the exploit, the practitioner must first construct the necessary cryptographic materials. Utilizing the specialized JWT Editor Keys interface, a new RSA key pair is generated and securely stored within the local environment. The practitioner then transitions to an external exploit server to build the malicious infrastructure required for the attack. The foundation of this infrastructure is an empty JSON Web Key Set, which is initially formatted as a simple JSON object containing an empty `keys` array.

```json
{
    "keys": [

    ]
}
```

The practitioner extracts the public component of their newly generated RSA key in the standardized JWK format and inserts it directly into the `keys` array on the exploit server.

Once stored, this configuration creates a live, publicly accessible endpoint hosting the adversarial key set. The resulting structure exactly mirrors the format expected by the vulnerable application during a legitimate external key retrieval operation.

```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "893d8f0b-061f-42c2-a4aa-5056e12b8ae7",
            "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw"
        }
    ]
}
```

### Token Forgery and Trust Subversion

Returning to the intercepted administrative request within the Burp Repeater module, the practitioner utilizes the JSON Web Token interface to meticulously manipulate the token structure. The token header must be carefully engineered to instruct the target server to query the adversarial infrastructure. First, the practitioner updates the existing `kid` parameter to perfectly match the identifier of the public key currently hosted on the exploit server, ensuring the backend application selects the precise cryptographic material upon retrieval.

Subsequently, a new `jku` parameter is injected into the token header, and its value is set to the absolute Uniform Resource Locator of the malicious key set hosted on the exploit server. Within the payload segment of the token, the practitioner elevates the subject claim, denoted by the `sub` parameter, to explicitly request the `administrator` role.

The final phase of the forgery involves cryptographically signing the manipulated token utilizing the corresponding adversarial private key generated in the initial steps. It is absolutely critical during this operation to instruct the signing tool to preserve the manually crafted header, ensuring that the injected `jku` and updated `kid` parameters are not inadvertently overwritten by default values.

Upon transmitting this forged token, the vulnerable server decodes the header, initiates an outbound HTTP request to the attacker controlled domain, retrieves the malicious public key, and successfully validates the adversarial signature. This profound trust failure completely subverts the authentication mechanism, granting the practitioner unrestricted access to the administrative panel. The practitioner concludes the exercise by navigating the application responses to locate the user management interface, eventually transmitting a final request to the `/admin/delete?username=carlos` endpoint to successfully fulfill the offensive objectives of the laboratory.

The instruction for this practical module is complete, and the session is currently paused awaiting authorization to proceed.