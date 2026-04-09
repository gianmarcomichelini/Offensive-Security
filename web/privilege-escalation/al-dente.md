## Al Dente - Privilege Escalation

### Locate the Profile Request 

Ensure your browser is routing traffic through Burp Suite. Perform a normal profile update on the Al Dente web application. Open the Proxy tab in Burp Suite, navigate to HTTP history, locate the `PUT /api/profile` request you just generated.

### Send to Repeater

Right click that request, select Send to Repeater. The Repeater tool allows you to manually modify and reissue HTTP requests without needing to interact with the browser.

### Inject the Payload

Switch to the Repeater tab. In the Request panel, find the JSON data at the bottom. Add the privilege escalation parameter to the existing data. Your modified JSON body should look similar to this:

```
{
  "username": "your_current_name",
  "bio": "your_current_bio",
  "role": "head_chef"
}
```

### Execute the Mass Assignment

Click the Send button. Review the Response panel on the right. You want to see a `200 OK` HTTP status code, which indicates the server accepted your injected role parameter. If "head_chef" fails, you can quickly edit the request in Repeater to try variations like "Head Chef", "admin", "HEAD_CHEF".

### Grab the Flag

Go back to the HTTP history, locate your previous `GET /api/secret-recipe` request (the one that previously returned a 403 Forbidden error), send it to Repeater. Click Send. Since your active session now has elevated privileges, you should receive a `200 OK` response containing the secret recipe and your CTF flag.