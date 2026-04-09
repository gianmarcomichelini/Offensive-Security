## EasyNotes - IDOR

### Understanding the Application

The application is a personal note-taking service where authenticated users can create and view their own private notes. On the surface it appears to be a straightforward and benign application, but the vulnerability lies not in what is visible in the browser interface, but in the underlying HTTP requests the browser makes silently on the user's behalf.

### Reconnaissance: Looking Under the Hood

The first and most important step is to open **Burp Suite** or the browser's **Network** tab in DevTools and observe every request generated as the student creates a note and then retrieves it. Modern web applications frequently expose a REST API that the frontend consumes transparently, meaning the student may see requests such as:

http

```http
GET /api/notes/57 HTTP/1.1
Host: training.olicyber.it
Cookie: session=...
```

The exercise hint poses a deliberately precise question: _"Are note IDs unique per user or shared across all users?"_ This is the critical observation to make. If the application assigns note IDs from a **single global counter** shared across all registered users, then the student's note with ID `57` sits numerically adjacent to notes belonging to entirely different accounts, meaning IDs `56`, `55`, `1` and so on all reference other users' private data.

### The Exploitation

Once the vulnerable API endpoint is identified, the request is sent to Burp Suite's **Repeater** module. The note ID is then systematically decremented:

http

```http
GET /api/notes/56 HTTP/1.1
GET /api/notes/1 HTTP/1.1
```

A server that returns another user's note content rather than an authorization error confirms the IDOR vulnerability. The flag will be found in one of these enumerated notes.

### What Makes This Exercise Different

Compared to Exercise 3, which also involved IDOR, EasyNotes introduces two additional layers of realism. First, the vulnerable parameter is not visible in the browser's address bar but is buried inside an **API call**, requiring the student to actively monitor network traffic rather than simply observing URLs. Second, the hint to check whether IDs are shared globally introduces the concept of **ID space analysis**, understanding how an application assigns identifiers is just as important as knowing that identifiers exist.

> **Key Takeaway:** IDOR vulnerabilities are not limited to visible URL parameters. Any client-accessible identifier, whether it appears in a REST API path, a JSON request body, or a WebSocket message, is a potential IDOR vector if the server does not enforce per-request authorization checks. Thorough reconnaissance of an application's full HTTP traffic, not just its visible interface, is essential to uncover these vulnerabilities in modern web applications.