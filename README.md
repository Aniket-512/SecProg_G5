# SecProg_G5
Group 5's implementation of a multi-party chat system based on the [GuardedIM Protocol Specification](https://docs.google.com/document/d/1i_fNjtrNLpYUVLcZBzeO10uNRBaJZhBCRBXXyLHZUto/)

## Architecture Summary
Multiple servers form a cluster, connected via WireGuard
- Network:
  - Group Server IP - 10.5.0.1/32
  - User IPs - 10.5.0.2/32 to 10.5.255.254/32
- Database:
  - CockroachDB - distributed database storage solution.
    (Standard PostgreSQL)
  - SQLite - 
    - Local message database
    - Server information database
- Application:
  - JSON payloads
  - Text has a maximum size of 4096 bits (4Kb) and files have a maximum size of 5MB.
  - Encryption: AES256-GCM
