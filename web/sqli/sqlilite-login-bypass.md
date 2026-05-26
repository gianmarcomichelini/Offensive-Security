## SQLiLite Logic Based Login Bypass

The initial supplementary exercise focuses on a fundamental vulnerability known as a logic based login bypass. This challenge, identified as SQLiLite, simulates a standard authentication mechanism where user input is insecurely handled, providing a practical environment to apply these foundational concepts at [https://play.picoctf.org/practice/challenge/304](https://play.picoctf.org/practice/challenge/304).

The architecture of such a vulnerability typically involves a web frontend submitting credentials to a backend server, which then directly concatenates these inputs into a database query without adequate sanitization. One must visualize a database table containing usernames and passwords, where the application attempts to verify access by querying for a matching row. If the application simply checks whether the query returns any records, the authentication logic becomes highly susceptible to manipulation.

The core exploitation strategy relies on altering the boolean logic of the underlying SQL statement. By injecting a carefully constructed payload into the username field, an external actor alters the grammatical structure of the query. The objective is to prematurely terminate the string literal intended for the username, append an `OR` operator, and introduce a tautology, such as the mathematical certainty `1=1`. Furthermore, a trailing SQL comment sequence is required to instruct the database engine to ignore the remainder of the original query, specifically neutralizing the password verification clause that the application attempts to append.



```SQL
admin' OR 1=1 -- 
```

> The successful execution of a logic based bypass within an authentication context highlights the critical danger of improper input handling, demonstrating how an attacker can completely circumvent access controls by forcing the backend database to evaluate a manipulated query as universally true.

```html
<p hidden>Your flag is: picoCTF{L00k5_l1k3_y0u_solv3d_it_9b0a4e21}</p>
```