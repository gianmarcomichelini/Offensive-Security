## NeonArcade - Privilege Escalation with Cookie Pollution


> x Exam (21)

(due to mass assignment)

The NeonArcade challenge focuses on bypassing a cryptographic protection mechanism by attacking the underlying application logic. Since the session cookies are properly signed by the server, direct tampering is impossible without knowing the secret key. The path forward relies on exploiting a mass assignment vulnerability within the profile update feature.

### **Exploitation Workflow**

**1. Initial Assessment and Session Analysis** We begin by registering a standard user account and logging into the application. Inspecting the session cookie reveals its structure, it typically consists of a base64 encoded JSON payload followed by a cryptographic signature. Attempting to manually modify the payload to include an elevated role invalidates the signature, causing the server to reject the session and log us out.

**2. Intercepting the Update Request** We navigate to the user settings page where profile modifications are allowed. Using an interception proxy like Burp Suite, we capture the POST or PUT request triggered when saving new profile data. The request body is usually a JSON object containing editable fields like `username`, `email`.

**3. Exploiting Mass Assignment** The core vulnerability exists because the backend framework blindly binds the incoming JSON payload directly to the user object in the database, it fails to whitelist strictly permitted fields. To exploit this, we inject a new key into the intercepted JSON payload aimed at modifying the user's authorization level. We append a privilege escalating parameter such as `"role": "admin"` alongside the standard profile data.

**4. Obtaining the newly Signed Cookie** We forward the manipulated request to the server. The backend processes the input, updates the corresponding database record with the new operator status, and regenerates the session state. Crucially, the server then issues a brand new session cookie reflecting these updated privileges. Because the application itself generated the cookie, the new signature is perfectly valid.

**5. Accessing the Target** We can decode the new base64 payload to verify that our role has been successfully updated. Armed with the new, legitimately signed cookie, we navigate directly to the operator panel endpoint to retrieve the flag.