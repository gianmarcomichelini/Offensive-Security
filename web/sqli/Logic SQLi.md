## Practical Application, Logic Based SQL Injection

The laboratory exercises transition into practical application through the OliCyber SQLi tutorial series, which is accessible at [https://training.olicyber.it/challenges#challenge-356](https://training.olicyber.it/challenges#challenge-356). The initial practical exercise focuses on executing a logic based SQL injection to bypass a simulated authentication mechanism. The target application is located at [http://web-17.challs.olicyber.it/logic](http://web-17.challs.olicyber.it/logic). In this scenario, the application receives input through a web console and directly embeds it into a query targeting a login table. The underlying backend utilizes MySQL through PyMySQL or SQLAlchemy. The vulnerable query structure takes the user input and places it directly within single quotes.

```SQL
SELECT * FROM login WHERE password = 'your_input'
```

To successfully exploit this vulnerability, the first step is to break the intended syntax, which is often tested by submitting a string containing a single quote, such as `foo' bar`, to observe the resulting database error. Once the application is confirmed to be vulnerable, a payload is crafted to manipulate the query's boolean logic. The goal is to append a tautology, such as `OR 1=1`, and neutralize the remainder of the legitimate query using a single line comment. In MySQL, the `--` sequence, which specifically requires a trailing space, instructs the database engine to ignore all subsequent characters on that line. A robust payload takes the following form:

```SQL
' OR 1=1 -- 
```

Logic based injections are highly effective for authentication bypasses because they alter the fundamental boolean logic controlling a critical security decision. However, this technique exhibits limitations when the objective is to extract arbitrary data from unrelated tables, which necessitates more advanced methodologies.

