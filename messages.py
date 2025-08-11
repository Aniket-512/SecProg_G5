# Group 5 Messages Module - JSON Protocol Implementation

import json
from datetime import datetime
from uuid import UUID

# Message size limits per specification
MAX_TEXT_SIZE = 512  # 4096 bits = 512 bytes as per specification
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB in bytes

# Supported message types
VALID_TYPES = {
    "message",
    "message_file",
    "group_message",
    "group_file",
    "user_status",
    "user_lookup_request",
    "user_lookup_response",
    "server_announce",
    "online_user_request",
    "online_user_response",
}

# Additional valid enum values
VALID_TO_TYPES = {"user", "group"}
VALID_PAYLOAD_TYPES = {"text", "file"}


def is_iso8601(timestamp):
    """
    Check if the timestamp string follows ISO 8601 format (e.g. '2025-07-24T03:00:00Z')
    """
    try:
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


def is_uuid(val):
    """
    Check if the given value is a valid UUID string
    """
    try:
        UUID(val)
        return True
    except ValueError:
        return False


def validate_message(data: dict):
    """
    Validate that the message dictionary follows GuardedIM JSON spec.
    Raise ValueError if anything is invalid, else return True.
    """

    # Check if "type" exists and is one of the accepted message types
    if "type" not in data or data["type"] not in VALID_TYPES:
        raise ValueError("Missing or invalid 'type' field.")

    msg_type = data["type"]

    def check_keys(keys):
        """
        Utility function to ensure all required fields are present.
        """
        for key in keys:
            if key not in data:
                raise ValueError(f"Missing key: {key}")

    # Common timestamp validation
    if "timestamp" in data and not is_iso8601(data["timestamp"]):
        raise ValueError("Invalid ISO 8601 timestamp format.")

    # Text-based direct or group message
    if msg_type in {"message", "group_message"}:
        check_keys(["from", "to", "to_type", "payload", "payload_type", "timestamp"])
        # CORRECTED: Check payload size in bytes (4096 bits = 512 bytes max)
        payload_bytes = len(data["payload"].encode('utf-8'))
        if payload_bytes > MAX_TEXT_SIZE:
            raise ValueError(f"Payload exceeds {MAX_TEXT_SIZE} byte text size limit.")
        if data["to_type"] not in VALID_TO_TYPES:
            raise ValueError("Invalid to_type value.")
        if data["payload_type"] not in VALID_PAYLOAD_TYPES:
            raise ValueError("Invalid payload_type value.")
        # Verify payload_type is 'text' for text messages
        if data["payload_type"] != "text":
            raise ValueError("payload_type must be 'text' for message/group_message types.")

    # File-based direct or group message
    elif msg_type in {"message_file", "group_file"}:
        check_keys(["from", "to", "to_type", "payload", "payload_type", "timestamp", "payload_id"])
        if len(data["payload"].encode('utf-8')) > MAX_FILE_SIZE:
            raise ValueError("Payload exceeds 5MB file size limit.")
        # payload_id is string per spec, not UUID
        if not isinstance(data["payload_id"], str) or len(data["payload_id"]) == 0:
            raise ValueError("payload_id must be a non-empty string.")
        if data["to_type"] not in VALID_TO_TYPES:
            raise ValueError("Invalid to_type value.")
        if data["payload_type"] not in VALID_PAYLOAD_TYPES:
            raise ValueError("Invalid payload_type value.")
        # Verify payload_type is 'file' for file messages  
        if data["payload_type"] != "file":
            raise ValueError("payload_type must be 'file' for message_file/group_file types.")

    # Online/offline status update
    elif msg_type == "user_status":
        check_keys(["user_id", "status", "timestamp"])
        if data["status"] not in {"online", "offline"}:
            raise ValueError("Invalid status value.")

    # Request to look up a user
    elif msg_type == "user_lookup_request":
        check_keys(["request_id", "from_server", "target_user_id", "timestamp"])
        # request_id is string per spec (e.g. "uuid_1234"), not strict UUID
        if not isinstance(data["request_id"], str) or len(data["request_id"]) == 0:
            raise ValueError("request_id must be a non-empty string.")

    # Response to a user lookup request
    elif msg_type == "user_lookup_response":
        check_keys(["request_id", "user_id", "online", "response_server", "timestamp"])
        if not isinstance(data["online"], bool):
            raise ValueError("'online' field must be boolean (True/False).")
        # request_id is string per spec
        if not isinstance(data["request_id"], str) or len(data["request_id"]) == 0:
            raise ValueError("request_id must be a non-empty string.")

    # Server announcing itself and its capabilities
    elif msg_type == "server_announce":
        check_keys(["server_id", "ip", "port", "capabilities", "timestamp"])
        if not isinstance(data["capabilities"], list):
            raise ValueError("capabilities must be a list.")
        # Validate port number
        if not isinstance(data["port"], int) or data["port"] <= 0 or data["port"] > 65535:
            raise ValueError("port must be a valid integer between 1-65535.")

    # Requesting list of online users
    elif msg_type == "online_user_request":
        check_keys(["server_id"])

    # Server responding with online users
    elif msg_type == "online_user_response":
        check_keys(["server_id", "online_users"])
        if not isinstance(data["online_users"], list):
            raise ValueError("online_users must be a list.")
        # Per specification, online_users can be list of strings ["UserB", "UserC", "UserD"]
        for user in data["online_users"]:
            if not isinstance(user, (str, dict)):
                raise ValueError("Each online user must be a string (user ID) or dict with user info.")
            # If it's a dict format, validate structure
            if isinstance(user, dict) and "user_id" not in user:
                raise ValueError("Each user dict must have 'user_id' field.")

    return True  # Message is valid 


def load_message(json_bytes: bytes):
    """
    Load message from encrypted/decrypted raw JSON bytes.
    Decode using UTF-8 and validate the structure.
    """
    try:
        decoded = json.loads(json_bytes.decode("utf-8"))
        validate_message(decoded)
        return decoded
    except Exception as e:
        raise ValueError(f"Invalid message format: {e}")


def dump_message(obj: dict) -> bytes:
    """
    Convert validated message dictionary into JSON-encoded UTF-8 bytes.
    Used for encrypting and sending.
    """
    validate_message(obj)
    return json.dumps(obj).encode("utf-8")