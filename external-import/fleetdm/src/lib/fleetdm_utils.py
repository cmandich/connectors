import ipaddress
from datetime import datetime, timedelta
import math
import logging
import uuid

LOGGER = logging.getLogger(__name__)

def cleanup_empty_strings(data: dict):
    """
    Remove key-value pairs from a dictionary where the value is an empty string.

    Args:
        data (dict): The dictionary to clean up.

    Returns:
        dict: A new dictionary with empty string values removed.
    """
    return {key: value for key, value in data.items() if value != ""}

def parse_timestamp(timestamp_str: str):
    """
    Parse a timestamp string into a datetime object.

    Args:
        timestamp_str (str): The timestamp string to parse.

    Returns:
        datetime: The parsed datetime object. If the input is empty, returns the current datetime.
    """
    return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ") if timestamp_str else datetime.now()

def parse_relationship_timestamp(timestamp_str: str, days: int = 2):
    """
    Parse a timestamp string and add a specified number of days.

    Args:
        timestamp_str (str): The timestamp string to parse.
        days (int): The number of days to add to the parsed timestamp.

    Returns:
        datetime: The resulting datetime object after adding the specified number of days.
    """
    return parse_timestamp(timestamp_str) + timedelta(days=days)

def ip_type(ip: str):
    """
    Determine the type of IP address (IPv4 or IPv6).

    Args:
        ip (str): The IP address to check.

    Returns:
        str: 'ipv4-addr' if the IP is IPv4, 'ipv6-addr' if the IP is IPv6, None if the input is invalid.
    """
    try:
        version = ipaddress.ip_address(ip).version
        return "ipv4-addr" if version == 4 else "ipv6-addr"
    except ValueError:
        return None

def remove_duplicates(data: list):
    """
    Remove duplicate items from a list based on their 'id' attribute.

    Args:
        data (list): The list of items to deduplicate.

    Returns:
        tuple: A tuple containing two lists:
            - A list of unique item IDs.
            - A list of unique items.
    """
    if not data:
        return [], []

    seen_ids = set()
    dedup_list = []

    for item in data:
        item_id = item.id  # Access the 'id' attribute directly
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            dedup_list.append(item)
    return list(seen_ids), data

def divide_and_round_up(numerator, denominator):
    """
    Divide the numerator by the denominator and round up the result.

    Args:
        numerator (float): The numerator for the division.
        denominator (float): The denominator for the division.

    Returns:
        int: The result of the division rounded up to the nearest integer.
    """
    if denominator == 0:
        raise ValueError("Denominator cannot be zero.")
    return math.ceil(numerator / denominator)

def generate_id(prefix:str, data:dict):
    """
    Generate a unique identifier based on the input data.

    Args:
        prefix (str): The prefix to use for the generated ID.
        data (dict): The data to use for generating the ID.

    Returns:
        str: The generated ID.
    """
    data_str = str(data).lower()
    id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data_str))
    return f"{prefix}--{id}"
