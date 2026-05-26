## DepartmentWiki - Stacked SQL Injection

> x Exam (24)

The workflow executed during this laboratory session represents a classic example of second order data exfiltration, specifically tailored to bypass architectural constraints that neutralize direct output channels. The methodology progresses through a systematic sequence of identification, payload formulation, state mutation, and final retrieval.

### Phase 1: Vulnerability Identification and Constraint Analysis

The initial phase requires a structural review of the application source code, specifically focusing on the Express routing logic and database interactions. The critical vulnerability resides within the search endpoint, where user input is concatenated directly into a raw SQL string and executed via the `db.exec()` function. A secondary analysis reveals the fundamental constraint of this specific function, which processes the injected statements but explicitly discards any returned tabular data. This behavior renders traditional UNION based extraction and boolean inference techniques entirely ineffective, necessitating a shift toward database state manipulation.

### Phase 2: Payload Construction for State Mutation

To circumvent the blind execution context, the exploitation strategy relies on crafting a stacked query designed to permanently alter the persistent state of the database. The objective is to force the database engine to extract the target data, specifically the administrative token from the internal configuration table, and write it into a publicly accessible location.

The resulting payload closes the initial application query and introduces an `UPDATE` command targeting a known record, such as the article with the primary key identifier of 1.



```SQL
'; UPDATE articles SET content = (SELECT value FROM internal_config WHERE key = 'admin_token') WHERE id = 1; --
```

### Phase 3: Payload Execution

The formulated payload is deployed directly through the vulnerable search interface. The application concatenates the payload into the raw execution path, processing the state mutation invisibly on the backend. Because the subsequent parameterized query fails to find the literal payload string, the frontend interface renders an empty search result. This silent execution confirms the success of the database manipulation without alerting standard monitoring mechanisms to anomalous data retrieval.

### Phase 4: Data Exfiltration and Verification

The final phase involves transitioning from the injection vector to a legitimate data retrieval vector. With the target database record permanently modified, the exfiltration is completed by utilizing the standard application functionality to access the compromised article.

> **Exfiltration Mechanism:** By searching for the article directly or navigating to its specific URL endpoint, the application is forced to perform a secure, parameterized query that retrieves the modified content field.

The frontend view subsequently renders the exfiltrated administrative token, completing the attack chain and successfully verifying the total compromise of the targeted confidential information.