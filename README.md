This is a python class for interacting with Active Directory via LDAP.

It is intended to be used in a self-service password reset application.
It focuses almost exclusively on password/account policy.

It does support [Server 2008r2's fine-grained password password policy]
(http://technet.microsoft.com/en-us/library/cc754544.aspx)

SUNY Geneseo uses this in production for our self-service AD password reset app.
It's not perfect, but it has been useful for us.

Requirements:
  - Python LDAP library

Expects:
  - Users can change their own password (SELF can Change Password in AD ACLs)
  - Leaf users of groups in CN=Administrators,CN=Builtin,<your AD base> can:
    - Look up password policies (domain-wide and fine-grained)
    - Set any user's password
  - To connect to one of your AD controllers via LDAP+SSL (generally port 636)

Provides:
  - Function to use admin credentials to bind to AD and
    change a user's password, which requires adherence to password policy.
  - Function to use admin credentials to set a user's password which
    mostly ignores password policy.
  - Function to immediately expire a user's password.
  - Function to get all password policies for a domain.
  - Function to load information about a user such as:
    - Which password policy applies to them
    - Are they locked/disabled/expired/password expired
    - When account/password expires
    - When password was last set

TODO:
  - Better sanitization of user input
  - ~~Better exception handling/throwing~~
  - ~~Force SSL (can only change passwords over SSL)~~
  - Clustered AD support (try next server in case of failure)
  - ~~Let AD do more calculation of things like:~~
    - ~~Effective PSO (msDS-ResultantPSO) (Server 2008+)~~
    - ~~Account locked, pw expired (msDS-User-Account-Control-Computed)
      (Server 2003+)~~
    - ~~Account lockout expiry (Lockout-Time) (Server 2000+)~~
