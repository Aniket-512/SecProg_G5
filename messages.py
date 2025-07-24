# Python code for Messages file using JSON.

import json
from datetime import datetime
from uuid import UUID

# Constants
MAX_TEXT_SIZE = 4096  # Max allowed size for text payloads (in bytes)
MAX_FILE_SIZE = 5 * 1024 * 1024  # Max allowed size for files: 5 MB

# Allowed message types as per GuardedIM spec
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
        if len(data["payload"]) > MAX_TEXT_SIZE:
            raise ValueError("Payload exceeds text size limit.")
        if data["to_type"] not in VALID_TO_TYPES:
            raise ValueError("Invalid to_type value.")
        if data["payload_type"] not in VALID_PAYLOAD_TYPES:
            raise ValueError("Invalid payload_type value.")

    # File-based direct or group message
    elif msg_type in {"message_file", "group_file"}:
        check_keys(["from", "to", "to_type", "payload", "payload_type", "timestamp", "payload_id"])
        if len(data["payload"]) > MAX_FILE_SIZE:
            raise ValueError("Payload exceeds file size limit.")
        if not is_uuid(data["payload_id"]):
            raise ValueError("Invalid payload_id UUID.")
        if data["to_type"] not in VALID_TO_TYPES:
            raise ValueError("Invalid to_type value.")
        if data["payload_type"] not in VALID_PAYLOAD_TYPES:
            raise ValueError("Invalid payload_type value.")

    # Online/offline status update
    elif msg_type == "user_status":
        check_keys(["user_id", "status", "timestamp"])
        if data["status"] not in {"online", "offline"}:
            raise ValueError("Invalid status value.")

    # Request to look up a user
    elif msg_type == "user_lookup_request":
        check_keys(["request_id", "from_server", "target_user_id", "timestamp"])
        if not is_uuid(data["request_id"]):
            raise ValueError("Invalid request_id UUID.")

    # Response to a user lookup request
    elif msg_type == "user_lookup_response":
        check_keys(["type", "request_id", "user_id", "online", "response_server", "timestamp"])
        if not isinstance(data["online"], bool):
            raise ValueError("Online must be boolean.")
        if not is_uuid(data["request_id"]):
            raise ValueError("Invalid request_id UUID.")

    # Server announcing itself and its capabilities
    elif msg_type == "server_announce":
        check_keys(["server_id", "ip", "port", "capabilities", "timestamp"])
        if not isinstance(data["capabilities"], list):
            raise ValueError("Capabilities must be a list.")

    # Requesting list of online users
    elif msg_type == "online_user_request":
        check_keys(["server_id"])

    # Server responding with online users
    elif msg_type == "online_user_response":
        check_keys(["server_id", "online_users"])
        if not isinstance(data["online_users"], list):
            raise ValueError("online_users must be a list.")
        for user in data["online_users"]:
            if not isinstance(user, dict):
                raise ValueError("Each online user must be a dict.")
            if "user_id" not in user or "name" not in user:
                raise ValueError("Each user must have 'user_id' and 'name'.")
            if not is_uuid(user["user_id"]):
                raise ValueError("Invalid user_id UUID in online_users.")

    return True  # Message is valid ✅


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

