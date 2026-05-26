## LabResults - IDOR

The scenario places the student in the role of a legitimate patient registered on a clinic portal called **MedLab Portal**. The application allows authenticated users to view their own lab results. The vulnerability lies in the fact that the application uses **sequential or otherwise predictable identifiers** to reference patient records, and it performs no server-side check to confirm that the requesting user is the rightful owner of the record being fetched.

### Reconnaissance with Burp Suite

The correct approach begins with careful observation rather than immediate exploitation. With Burp Suite configured as an intercepting proxy, the student navigates the portal normally, logging in and viewing their own results. Every HTTP request the browser generates is captured and inspected in Burp's **Proxy** tab.

At some point in this flow, a request will appear that fetches the authenticated user's own lab results. This request will contain a predictable identifier, most likely a small integer, embedded in the URL path, as a query parameter, or within the request body. For example, the request might look like:

```http
GET /results/4 HTTP/1.1
Host: ...
Accept-Language: en-US,en;q=0.9
```

### The Exploitation

Once the vulnerable parameter is identified, the request is sent to Burp's **Repeater** module. The identifier is then modified to reference adjacent records, for instance changing `id=42` to `id=41` or `id=1`, and the modified request is forwarded to the server. If the server returns another patient's confidential lab results without raising an authorization error, the IDOR vulnerability is confirmed and exploited.
