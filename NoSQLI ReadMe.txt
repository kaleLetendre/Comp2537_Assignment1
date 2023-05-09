NoSQLI is a tool that opens a particular site and attempts to hack it using set of NoSQL Injection attacks.
The site checks to see if the output is different between the hack and normal behaviour.
If a difference is detected, it will assume that the attack was successful.

Example of how to use:
nosqli scan -t http://localhost:3000/nosql-injection?user=patrick