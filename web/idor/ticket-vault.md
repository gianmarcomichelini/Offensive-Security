## TicketVault - IDOR

We now transition to the subsequent laboratory exercise titled TicketVault, which simulates the internal ticketing system utilized by a security operations center, where you are initially positioned as a newly recruited support agent. Upon accessing the IT Support Portal and completing the registration and authentication process, you are presented with your user profile, which clearly designates your role as an agent within the IT Support department, establishing a baseline of low-privileged access. The primary objective of this exercise requires you to retrieve a specific confidential ticket that is strictly reserved for higher-tier personnel, given that the application ostensibly restricts visibility based on assigned user roles.

When you navigate the application and observe the network traffic using an interception proxy, you will notice that the client application requests ticket data by sending an HTTP GET request to specific endpoints, which are structured with a sequential numerical identifier at the end of the uniform resource locator. To exploit the underlying vulnerability, you must directly manipulate this identifier, changing the requested path to `/api/tickets/1`, which represents the first and potentially most sensitive record in the database. When you forward this modified request, which includes your standard session cookie to maintain authentication, the backend server fails to verify whether your specific agent account possesses the requisite authorization to view this particular object, which constitutes a classic **Insecure Direct Object Reference** vulnerability. Because the application strictly validates authentication but entirely neglects the authorization phase for direct object access, it processes the request and returns a successful 200 OK status code, alongside the complete JSON response body containing the critical internal security breach report, where you will find the final incident response code.



```JSON
{
  "id": 1,
  "title": "CRITICAL - Internal Security Breach Report",
  "description": "CONFIDENTIAL - IT SECURITY MANAGER ONLY\n\nDuring routine log analysis on 2026-03-14, the SIEM flagged anomalous query patterns against the production database (db-prod-02). Investigation confirmed unauthorized data extraction between 02:47 and 03:12 UTC.\n\n--- Incident Details ---\nAttack vector: Exposed API endpoint with missing authorization check\nAffected systems: auth-prod-01, db-replica-03\nData exposed: User session tokens (est. 2,300 records)\nEvidence: /var/log/incident/breach_20260314.tar.gz\n\n--- Response Actions ---\n1. Rotated all active session tokens\n2. Patched the vulnerable endpoint\n3. Engaged external forensics team\n\nIncident Response Code: offsec{1d0r_t1ck3t_DQ02MuALcd42f02K}\n\nThis ticket is restricted to IT Security management. Do not distribute.",
  "status": "open",
  "priority": "critical",
  "category": "Security",
  "createdBy": "SIEM Alert System",
  "createdAt": "2026-03-14T02:47:00Z",
  "updatedAt": "2026-03-14T09:30:00Z"
}
```

![[TicketVault - IDOR.png | 400]]

> **Insecure Direct Object Reference (IDOR):** This vulnerability arises when an application provides direct access to database objects based on user-supplied input, where the failure to implement robust server-side access control checks allows an attacker to bypass authorization and access sensitive resources belonging to other users or higher privileged roles.