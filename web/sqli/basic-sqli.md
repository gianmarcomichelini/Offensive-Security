## Basic SQLi - Authentication Bypass
The third exercise requires a practical evaluation of a standard login form located at the "My secret site" challenge, which can be accessed via [https://training.olicyber.it/challenges#challenge-48](https://www.google.com/search?q=https://training.olicyber.it/challenges%23challenge-48). The page shows a standard login form with a username and a password field. Invalid credentials produce the message "Incorrect!".

The primary objective is to bypass the login form using a classic logic-based SQL injection. The workflow involves interacting directly with the login form utilizing a standard browser or an interception proxy like Burp Suite. Because the application evaluates the username and password fields via a backend database query, providing a crafted string can alter the boolean logic of that query. The solution requires submitting a payload into the username field that effectively closes the intended string literal and introduces a tautology, forcing the authentication check to evaluate as true and retrieve the flag.

```SQL
' OR '1'='1
```

