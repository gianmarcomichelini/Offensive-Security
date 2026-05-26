## JWT authentication bypass via kid header path traversal

The current practical exercise focuses on a severe implementation flaw where a web application securely handles session management through JSON Web Tokens but insecurely retrieves the cryptographic verification key. In this specific architecture, the backend application utilizes the Key ID parameter, denoted as the `kid` header, to directly reference and fetch the required key from the local filesystem.

> **Key Identifier Path Traversal** occurs when an application insecurely utilizes a user controllable header parameter to dynamically construct a filesystem path for retrieving the cryptographic verification key, exposing the backend validation process to arbitrary local file inclusion.

### The Vulnerability Architecture

In a properly hardened environment, the `kid` parameter functions simply as an alphanumeric index used to query a secure database or an isolated keystore. However, when developers utilize this input to interact directly with the operating system file structure without implementing rigorous input sanitization, an adversary can inject standard directory traversal sequences. By utilizing sequences such as `../`, the attacker forces the application to traverse outside the intended cryptographic directory and read arbitrary files residing on the host server.

The most devastating application of this vulnerability against symmetric signing algorithms involves targeting a predictable, static system file. In Unix operating systems, the `/dev/null` device file represents an ideal target because it acts as a data sink and consistently returns an empty string when read by an application. If an adversary forces the server to utilize `/dev/null` as the verification secret, the application will attempt to validate the token's HMAC signature utilizing an empty string as the foundational cryptographic key.

### Adversarial Key Generation Workflow

The practical exploitation begins with the preparation of the corresponding adversarial cryptographic materials within the local interception proxy. After authenticating into the application utilizing the standard credentials and observing the access denial at the restricted `/admin` endpoint, the practitioner navigates to the dedicated JWT Editor Keys interface to forge the necessary secret.

Because the ultimate objective is to forge a token signed with an empty string to match the behavior of the `/dev/null` file, the practitioner must generate a new Symmetric Key in the JSON Web Key format. A technical constraint exists within the Burp Suite extension, which prohibits the signing of tokens utilizing a completely empty string value. To circumvent this limitation, the practitioner generates the default symmetric key and manually alters the key value property, designated as `k`, to contain the specific Base64 encoded representation of a null byte.

```json
{
  "kty": "oct",
  "k": "AA=="
}
```

The string `AA==` accurately decodes to a null byte, providing the necessary mathematical equivalent to successfully forge the signature in the subsequent phases of the attack. Once this modified symmetric key is saved to the local repository, the practitioner possesses the required materials to initiate the payload manipulation.

### Token Forgery and Traversal Execution

With the required adversarial cryptographic materials prepared, the practitioner transitions to the active exploitation phase within the local interception proxy. Returning to the intercepted HTTP request directed toward the restricted administrative endpoint, the practitioner utilizes the specialized JSON Web Token editor to manipulate the token structure.

The critical manipulation occurs within the token header, where the practitioner completely replaces the legitimate value of the `kid` parameter with a comprehensive directory traversal payload.

```json
{
  "alg": "HS256",
  "kid": "../../../../../../../dev/null",
  "typ": "JWT"
}
```

This specific sequence of traversal characters forces the backend application to navigate from its current working directory to the root of the filesystem, ultimately resolving to the `/dev/null` device file. By executing this path resolution, the application inadvertently loads an empty string into its memory space to serve as the cryptographic secret for the subsequent signature validation process.

Concurrently, the practitioner must define the final authorization objective by modifying the token payload. The subject claim, identified by the `sub` parameter, is altered to request the `administrator` identity, ensuring that upon successful cryptographic validation, the application grants the highest level of system privileges.

```json
{
  "sub": "administrator",
  "iat": 1516239022,
  "exp": 1713193600
}
```

The final step in forging the token involves cryptographically signing the manipulated structure. The practitioner instructs the specialized extension to sign the token utilizing the previously generated symmetric key containing the encoded null byte. It is of paramount importance during this operation to explicitly select the configuration option that prevents the extension from automatically modifying the header, guaranteeing that the meticulously injected directory traversal sequence remains entirely intact.

The practitioner transmits the newly forged token to the target server. The vulnerable backend application parses the header, traverses the local filesystem to retrieve the contents of the `/dev/null` file, and seamlessly utilizes the resulting empty string to validate the HMAC signature computed by the practitioner. This profound logical failure completely subverts the authentication architecture, granting unrestricted access to the administrative panel. The practitioner concludes the practical engagement by parsing the server response to locate the specific user management endpoint, subsequently transmitting a final HTTP request to `/admin/delete?username=carlos` to fulfill the offensive objectives.