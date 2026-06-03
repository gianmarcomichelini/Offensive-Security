## SQLi - Exploiting Registration Flows

The fourth exercise, known as "Admin's Secret", introduces a critical paradigm shift regarding where vulnerabilities are typically discovered. The challenge page at [[http://adminsecret.challs.olicyber.it/](https://training.olicyber.it/challenges#challenge-44)]([https://www.google.com/search?q=http://adminsecret.challs.olicyber.it/](https://training.olicyber.it/challenges#challenge-44)) has two links, specifically Login and Registrazione. The challenge description also provides the PHP source code for both login.php and register.php. A thorough architectural analysis requires reading the source code carefully, revealing that one page is secure and the other is not.

### Constructing the Successful Payload

The objective of this challenge is to gain administrative access by exploiting a vulnerability within the registration flow. Because the login interface is strictly secure, the architectural flaw resides entirely within the registration mechanism. The application source code reveals that the database query incorporates user input directly into an INSERT statement without proper parameterization.

> Any database operation that integrates user input directly into the command string, including INSERT operations, creates a critical vulnerability that allows attackers to manipulate the fundamental structure of the database.

Based on the error message analyzed previously, the backend application attempts to execute an insertion command that defaults new accounts to a standard privilege level. To formulate the correct solution, the attacker must supply a crafted payload into the username registration field that closes the initial string literal, defines a unique username to avoid primary key collisions, provides a corresponding password, sets the administrative boolean flag to true, and finally neutralizes the remainder of the legitimate query.

If the attacker registers utilizing the specific username payload below, alongside any arbitrary password, the database will process the manipulated command.



```SQL
new_admin_user', 'secure_password', true); -- 
```

When the vulnerable PHP script processes this exact input, the backend dynamically constructs and executes the following complete SQL statement against the database infrastructure.



```SQL
INSERT INTO users(username,password,admin) VALUES ('new_admin_user', 'secure_password', true); -- ', 'arbitrary_form_password', false);
```

This executed command successfully creates a brand new account named `new_admin_user` with the password `secure_password`, while forcefully elevating its privilege level to true. The trailing sequence ensures the original parameters intended by the developer are completely ignored by the database engine. Following this successful registration, the solution concludes by navigating to the secure login page and authenticating with these newly minted administrative credentials.