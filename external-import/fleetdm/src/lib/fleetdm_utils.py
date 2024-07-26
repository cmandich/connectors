import ipaddress
from datetime import datetime, timedelta
import math


def cleanup_empty_string_in_dict(data: dict = {}):
    """
    Remove key-value pairs from a dictionary where the value is an empty string.

        Args:
        data (dict): The dictionary to clean up.

            Returns:
        dict: A new dictionary with empty string values removed.
    """
    return {key: value for (key, value) in data.items() if value != ""}


def parse_timestamp(timestamp_str: str):
    """
    Parse a timestamp string into a datetime object.

    Args:
        timestamp_str (str): The timestamp string to parse.

    Returns:
        datetime: The parsed datetime object. If the input is empty, returns the current datetime.
    """
    if timestamp_str:
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
    else:
        timestamp = datetime.now()
    return timestamp


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
        ipaddress_version = ipaddress.ip_address(ip).version
        if ipaddress_version == 4:
            return "ipv4-addr"
        elif ipaddress_version == 6:
            return "ipv6-addr"
        else:
            return None
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
        item_id = item.get("id")
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            dedup_list.append(item)
    return list(seen_ids), dedup_list

def divide_and_round_up(numerator, denominator):
    if denominator == 0:
        raise ValueError("Denominator cannot be zero.")
    result = numerator / denominator
    rounded_up_result = math.ceil(result)
    return rounded_up_result
