# QR Drop - Command Injection 

> x Exam (27)

This challenge is a "blind" command injection challenge.
Even though the application does not return the output of the command, we can make it return the flag by encoding it in the QR code itself.

The vulnerable line of code is:

```
      const cmd = `qrencode -t PNG -o ${outputPath} -s 8 -m 2 '${url}'`;
```

Where the `url` variable is user-controlled and is not properly sanitized.
So we can inject the following command to get the flag:

```
    '$(cat /flag.txt)'
```

Notice that we need to add an extra pair of single quotes to properly close the string in the original command and avoid syntax errors.
