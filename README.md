# SecProg_G5
Group 5's implementation of a multi-party chat system based on the [GuardedIM Protocol Specification](https://docs.google.com/document/d/1i_fNjtrNLpYUVLcZBzeO10uNRBaJZhBCRBXXyLHZUto/)

## Project Summary 
The main goal of this project is to build a working command-line chat system where users can send and receive encrypted messages and files. Our system supports both direct and group communication.

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

## Files in the Project

- client.py
    - Connects to server, sends/receives messages & files, stores in SQLite
- server.py
    - Handles routing, stores user presence in CockroachDB
- crypto.py
    - AES256-GCM functions, nonce generation, key management
- messages.py
    - Defines and Validates JSON Message formats
- database.py
    - Defines schema and interfaces with CockroachDB + local SQLite 
- README.md

## Message Types Supported

| Message Type             | Description                                               |
|--------------------------|-----------------------------------------------------------|
|  message                 | Normal text message to another user                       |
|  message_file            | Sending a file to another user                            |
|  group_message           | Text message to a group                                   |
|  group_file              | File message to a group                                   |
|  user_status             | Online/offline status notification                        |
|  user_lookup_request     | Ask for a user’s status and info                          |
|  user_lookup_response    | Response with user details                                |
|  server_announce         | Used to announce the details of the server in the network |
|  online_user_request     | Ask the server who’s online                               |
|  online_user_response    | Response with online users ID list                        |

## Steps to run the app
### 1. Start the server: python server.py
### 2. Start the client: python client.py
### 3. Send the message: Navigate and follow the onscreen menu to send text or files to other users/groups.


## Notes and Constraints 
- Timestamps must be in ISO8601 format (UTC)
- Messages exceeding size limits are rejected during validation
