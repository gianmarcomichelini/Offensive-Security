## Make a Wish - URL Query String Modification

The challenge is available at: **[https://training.olicyber.it/challenges#challenge-47](https://training.olicyber.it/challenges#challenge-47)**

The regular expression `/.*/i` matches **any string**, including an empty one, because `.*` means zero or more of any character. There is no string value that could ever cause `preg_match` to return `0` here. If the developer's intention was to block certain inputs, this regex is entirely useless, but more importantly, the flag appears to be **unreachable by design** when sending any normal string.

### The Actual Exploit: Forcing a PHP Error

The key lies in how `preg_match` behaves when it receives an **array** instead of a string as its subject argument. PHP's `preg_match` returns:

- `1` when the pattern matches a string
- `0` when the pattern does not match a string
- `FALSE` when an **error** occurs, such as receiving an unexpected type

```php
preg_match("/.*/i", "hello")   // returns 1 → if TRUE → "No"
preg_match("/.*/i", [])        // returns FALSE → if FALSE → flag!
```

Sending an array via the query string is achieved with the following syntax:
```
?richiesta[]=<anything>
```

PHP reconstructs this as a native array, passes it to `preg_match`, which cannot operate on an array, silently returns `FALSE`, and the `if` condition evaluates as falsy, falling through to the `else` branch that prints the flag.

> **Key Takeaway:** The vulnerability here is not about finding a string that bypasses the regex, it is about breaking the assumption that the input will always be a string. `preg_match` returning `FALSE` is indistinguishable from `0` in a loose boolean context, and the developer never accounted for this failure mode. The fix is to explicitly check the return value with strict equality: `if(preg_match(...) === 1)`.