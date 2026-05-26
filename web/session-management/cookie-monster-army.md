## Cookie Monster Army - Cookie Manipulation


> x Exam (18)


### Exploration and Identity Reflection

The primary objective of this exercise is to successfully impersonate the administrative user by actively tampering with a session cookie. The target application is hosted at [http://cma.challs.olicyber.it](http://cma.challs.olicyber.it/), and it requires the creation of a new account followed by a successful login. Upon authenticating, it is essential to observe the resulting welcome page, noting whether a flag is displayed and identifying exactly what information the application reflects regarding the current user's identity.

### Session State and Base64 Encoding

To understand how the application maintains this authenticated state, one must utilize the browser's Developer Tools, navigating specifically to the Application tab or Storage tab to visually inspect the cookies set for the target domain. Within this interface, one should search for a specific cookie that was entirely absent prior to authentication, analyzing its visual structure to determine if it resembles a high entropy random token or possesses a recognizable format.

If the cookie value consists exclusively of alphanumeric characters along with characters like plus or slash, this provides a strong cryptographic indicator that the string is Base64 encoded. To proceed, one must copy this encoded value and decode it, utilizing tools such as the Burp Suite Decoder tab, the browser's JavaScript console via the `atob()` function, or standard command line utilities. Upon decoding the string, the underlying fields become readable, and the registered username should be clearly visible.

> **Base64 Encoding**: Base64 is an encoding standard, not an encryption standard, representing a fully reversible mathematical transformation designed strictly for transporting binary data across text based protocols. It provides absolutely no confidentiality and no integrity guarantees, meaning anyone observing the traffic can decode it, modify the contents, and re-encode it, making it fundamentally insecure for protecting sensitive data on its own.

### Forging the Cookie and Privilege Escalation

The actual exploitation phase involves a direct manipulation of this payload, where one replaces the existing username field with the string `admin`, ensuring all other fields remain completely unchanged. The modified string must then be encoded back into the Base64 format, which can be accomplished using standard command line tools, before physically overwriting the active session cookie value directly within the DevTools interface or through Burp Suite. By reloading the application, one can observe whether the server accepts the forged cookie and grants administrative access, highlighting a fundamentally broken session mechanism that blindly trusts client supplied data without proper server side verification.

