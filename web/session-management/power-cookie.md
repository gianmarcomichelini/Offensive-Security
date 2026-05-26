## Power Cookie - Authorization Manipulation

### Analysis of the Client-Side Authorization Fallacy

In this laboratory scenario, the "Online Gradebook" application demonstrates a critical architectural failure where authorization is delegated to the client rather than being enforced by the server. When a user interacts with the "Continue as guest" button, the application executes a front-end routine that sets a specific cookie before redirecting the browser to `/check.php`. By examining the page source or the associated JavaScript, it becomes evident that the button's primary function is to locally define the user's role through a cookie assignment.

### Identification and Escalation Methodology

The technical workflow for exploiting this vulnerability follows a structured approach of inspection and tampering:

- **State Inspection**: Utilizing the **Application** tab in Browser DevTools or an intercepting proxy like **Burp Suite**, one must examine the cookies set for the domain after clicking the guest button.
    
- **Vulnerability Discovery**: One will identify a cookie whose name (e.g., `admin`) or value (e.g., `0` or `false`) clearly maps to the user's privilege level.
    
- **Direct Manipulation**: By double-clicking the value field in DevTools or intercepting the request in Burp, the attacker changes the value to reflect an administrative state (e.g., changing `0` to `1` or `false` to `true`).
    
- **Access Verification**: Reloading the `/check.php` page with the tampered cookie causes the server to grant administrative access, as it implicitly trusts the client-supplied role without server-side verification.
    

> **Key Takeaway**: This exercise illustrates that cookies should only serve as references to server-side state. Any authorization decision based on data that the user can freely modify is fundamentally insecure, as the user effectively becomes the authority on their own permission level.


<div class="page-break"></div>
