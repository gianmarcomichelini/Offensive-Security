## Flags Shop - Input Validation

The challenge is available at: **[https://training.olicyber.it/challenges#challenge-43](https://training.olicyber.it/challenges#challenge-43)**

The scenario is straightforward: an online shop sells a flag at a price the user cannot afford given their current balance. The objective is to purchase it anyway.

### The Fundamental Principle: Never Trust the Client

Before diving into the first exercise, it is worth establishing the foundational principle that underpins every vulnerability in this laboratory. Every piece of data that originates from the client, whether it is a form field, a URL parameter, a cookie, or an HTTP header, is entirely under the attacker's control. A server that makes decisions based on client-supplied values without independently verifying them is, by definition, vulnerable.

This is not merely a theoretical concern. Developers routinely make the mistake of treating certain client-side data as implicitly trustworthy, simply because the normal user interface does not expose it directly to the user. The first two exercises exist precisely to dismantle that assumption.


### Exploring the Attack Surface

The first step in any web attack is to identify the **attack surface**, meaning all the points where user-controlled data enters the application. The most obvious inputs are visible form fields, but a disciplined attacker treats the entire HTTP request as potential input. This includes URL parameters, the request body, cookies, and HTTP headers.

In this case, the purchase form contains a **hidden `<input>` field** that carries the item's price, named `costo`, directly to the server. Hidden fields are invisible in the rendered browser UI, but they are fully present in the HTML source and can be read and modified freely by anyone who inspects the page.

html

```html
<input type="hidden" name="costo" value="1000">
```

This is the critical observation: **hidden does not mean secret**. The server receives this value from the client and, if it trusts it blindly, will process whatever number the attacker chooses to send.

### The Exploitation with Burp Suite

With **Burp Suite** configured as a proxy and interception enabled, clicking the buy button captures the outgoing POST request before it reaches the server. The request body will contain the `costo` parameter with its original value. The attacker simply modifies this value to something within their balance, for example `1`, and forwards the modified request.

> **Key Takeaway:** The server should never accept a price from the client. The price of any item must be looked up server-side from a trusted data source, such as a database, using the item's identifier. The client should only send _what_ they want to buy, never _how much_ they are willing to pay for it.

### Reflection

The vulnerability exists because the developer delegated a security-critical decision, the price of a transaction, to the client. The correct fix is architectural: the server must retrieve the authoritative price independently, using only the item ID supplied by the client, and must never read or honor a price value coming from the request body.


<div class="page-break"></div>
