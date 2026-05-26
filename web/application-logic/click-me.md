## Click Me - Cookie Manipulation

The challenge is available at: **[https://training.olicyber.it/challenges#challenge-46](https://training.olicyber.it/challenges#challenge-46)**

The scenario presents a clicking game where the user must accumulate an enormous number of cookies, in the tens of millions, by clicking a button on the page. The objective is to obtain the flag without performing anywhere near the required number of clicks.

### How the Score Is Tracked: Client-Side Cookies

Opening the browser's **DevTools** and inspecting the page source reveals the mechanism behind the score tracking. The current score is stored in a **client-side cookie**, a small piece of data that the browser stores locally and automatically attaches to every HTTP request sent to the same domain via the `Cookie` header.

This is the fundamental architectural mistake. Because the score lives in a cookie, and because cookies are entirely readable and writable by the client, the server is effectively asking the attacker to self-report their own score. When the page loads or refreshes, the server reads the `cookies` value from the incoming request header and checks whether it exceeds the required threshold. It performs no independent verification of whether that score was legitimately earned.

> **Key Takeaway:** Any value stored on the client, whether in a cookie, in `localStorage`, or in a hidden field, must be treated as untrusted. Server-side state, stored in a session tied to the authenticated user on the server, is the only reliable mechanism for tracking sensitive values like scores, balances, or progress.

### Exploitation Path 1: Burp Suite Repeater

The most direct exploitation approach uses **Burp Suite**. After clicking the image a few times to generate an initial score and trigger the cookie creation, the student enables interception and refreshes the page. The intercepted GET request will contain a `Cookie` header similar to the following:

```http
Cookie: cookies=7
```

From here, the request is sent to the **Repeater** module by right-clicking and selecting "Send to Repeater." In Repeater, the cookie value is modified to a number exceeding the threshold, for example:

```http
Cookie: cookies=99999999
```

Clicking "Send" dispatches the modified request directly to the server, which reads the inflated score, determines the threshold has been met, and returns the flag in the response body.



> **Important Observation:** This exercise deliberately surfaces a broader lesson. There are almost always multiple vectors available to exploit a given vulnerability. A skilled attacker considers all of them, choosing the most reliable or stealthy path depending on the context. Modifying the cookie directly is the most immediate approach, but response tampering and console injection are equally legitimate techniques that become indispensable in more constrained scenarios.


<div class="page-break"></div>
