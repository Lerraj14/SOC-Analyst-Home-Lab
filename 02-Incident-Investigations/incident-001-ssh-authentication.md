Incident Report #001
Simulated event

Investigation field	Details
Incident type	Failed SSH authentication
Severity	Informational / Low
Host affected	SOC-Ubuntu-01
Target account	fakeuser
Source	Windows host IP (verify in logs)
Detection source	Ubuntu system journal
Status	Pending investigation


Investigation objectives
1. Identify the attempted username.
2. Determine the source IP address.
3. Establish the timestamp.
4. Check for subsequent successful authentication.
5. Determine whether further investigation is necessary.
   
   Initial assessment
An unsuccessful SSH authentication attempt was deliberately generated during a controlled security exercise. No compromise is established. Further authentication log review is required to establish whether any unauthorized access occurred.
