## UNION Based SQL Injection
### Initial Reconnaissance at the Target Endpoint

The second challenge in our training series requires us to transition from manipulating logic to actively stealing information from the database. We will analyze the environment located at [http://web-17.challs.olicyber.it/union](http://web-17.challs.olicyber.it/union). As we begin our interaction with the application console, we must first observe the exact query being executed by the backend. The server is running the statement:

```SQL
SELECT * FROM dummy_data WHERE id='<val>'
```

Because the application compares our input directly against an identifier, we can assume the expected value is an integer. Submitting the integer 1 returns a single row containing six distinct fields, specifically `1, dummy value1, 3, another_value1, lollo, 4`. Each of these individual values originates from a specific column within the `dummy_data` table. While a standard logic injection can reveal the entire contents of this table, an analysis shows it only holds placeholder values like `4, pls stop, 0, example, lollo, 17`, confirming the actual flag is located elsewhere.

### The Mechanics of UNION SELECT

> The UNION keyword allows an attacker to combine the result of multiple SELECT expressions into a single consolidated result set. This mechanism effectively permits the execution of a secondary, completely arbitrary SELECT query, appending its retrieved data to the results displayed by the initial query.

By leveraging this technique, we can interrogate entirely different tables beyond the one originally targeted by the application. The fundamental mathematical constraint of this attack requires that both the original SELECT statement and our newly injected SELECT statement return the exact same number of columns. Because our reconnaissance confirmed the initial query returns exactly six columns, our injected payload must similarly define six columns. We can test this capability with the following payload:


```SQL
1' UNION SELECT 1,2,3,4,5,'6

-- or 

1' UNION SELECT 1,2,3,4,5,6 -- <- remember the last whitespace
```

This specific structure elegantly handles the trailing syntax. By intentionally leaving the final numeric value without a closing quote, the application itself will append its own closing quote to complete the string literal without generating a syntax error. Alternatively, we can terminate the injection using a tautological expression that integrates with the final quotation mark:



```SQL
' UNION SELECT first_col,sec_col,3,4,5,6 FROM table WHERE col_x='<val>' AND '1'='1
```

### Database Fingerprinting

Before we can locate the hidden flag, we must accurately identify the specific database technology driving the backend application. Different database engines utilize completely different methods to retrieve version information, and we must test various functions until we receive a positive response. Common methodologies include `version()` for MySQL and PostgreSQL, `@@VERSION` for Microsoft SQL Server, and `sqlite_version()` for SQLite environments. We can dynamically replace one of our numerical placeholders with the `version()` function:



```SQL
1' UNION SELECT 1, version(), 3, 4, 5, '6
```

Executing this payload might return a version string such as `9.5.0`, confirming we are interacting with a MySQL instance.

### Schema Enumeration and Flag Extraction

With the knowledge that the backend relies on MySQL, we can exploit the built in `information_schema` to discover the internal structure of the database. This specialized schema acts as a comprehensive catalog of metadata. The `tables` collection lists all accessible tables, utilizing columns like `table_name` and `table_schema`. Similarly, the `columns` collection provides an exhaustive list of every column across all tables, utilizing fields like `column_name`, `table_name`, and `table_schema`. 



```sql
1' UNION SELECT table_name,2,3,4,5,6 FROM information_schema.tables -- 
```


Output:

![[image_union_schema.png | 300]]


To efficiently filter out irrelevant system data and focus only on the current application environment, we append a condition utilizing the `DATABASE()` function. We enumerate the relevant tables using this payload:



```SQL
1' UNION SELECT table_name,2,3,4,5,6 FROM information_schema.tables WHERE table_schema = DATABASE() -- 
```

Output:
![[image_union_database.png | 300]]

After identifying the critical tables, we map their respective columns:



```SQL
1' UNION SELECT table_name,column_name,2,3,4,5 FROM information_schema.columns WHERE table_schema = DATABASE() -- 
```

Output:
![[image_union_columns.png | 300]]

Once our enumeration reveals that the flag is stored within the `flag` column of a table named `real_data`, we construct the final extraction payload to retrieve our objective:

```SQL
1' UNION SELECT id,flag,3,4,5,6 FROM real_data -- 
```

This process conclusively demonstrates how a UNION based injection provides comprehensive read access across an entire database architecture, provided the column count is known and the application actively displays query results to the user.