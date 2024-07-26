import logging
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter, Retry

from .fleetdm_constants import BASE_URI_PATH, FLEETDM_SESSION_TIMEOUT, GET_HOST_PARAMS

LOGGER = logging.getLogger(__name__)


class FleetDMHostList:
    """
    A class to interact with the FleetDM API for retrieving host information.

    Attributes:
        url (str): The base URL for the FleetDM API.
        api_key (str): The API key for authentication.
        next_page (bool): A flag indicating if there is a next page.
        headers (dict): The headers to be sent with each request.
    """

    def __init__(self, base_url: str, api_key: str, per_page: int = 100):
        """
        Initialize the FleetDMHostList.

        Args:
            base_url (str): The base URL for the FleetDM API.
            api_key (str): The API key for authentication.
            per_page (int): The number of hosts to retrieve per page. Defaults to 100.
        """
        self.base_url = base_url
        self.url = urljoin(base_url, BASE_URI_PATH)
        self.api_key = api_key
        self.next_page = True

        self.__page = 0
        self.__per_page = per_page
        self.__host_count = 0

        # Set the headers
        self.__headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        self.session = self.__session()

    def __session(self):
        """
        Create a session object for making requests.

        Returns:
            requests.Session: A session object for making requests.
        """
        session = requests.Session()
        session.headers.update(self.__headers)
        retries = Retry(total=5, backoff_factor=1)
        session.mount("http://", HTTPAdapter(max_retries=retries))
        session.mount("https://", HTTPAdapter(max_retries=retries))
        return session

    def __update_page(self):
        """
        Increment the page number by one.

        This method updates the internal page counter by incrementing it by one.
        """
        LOGGER.debug(f"Updating page from {self.__page} to {self.__page + 1}.")
        self.__page += 1

    def __update_has_next(self, hosts_list: list = []):
        """
        Update the flag indicating if there is a next page.

        This method checks the length of the hosts list and updates the next_page flag.

                Args:
            hosts_list (list): The list of hosts retrieved from the current page.
        """
        LOGGER.debug("Checking if there is a next page.")
        if len(hosts_list) < self.__per_page:
            self.next_page = False

    def __update_host_count(self, count: int = 0):
        """
        Update the total host count.

        This method increments the internal host count by the specified count.

        Args:
            count (int): The number of hosts to add to the total count. Defaults to 0.
        """
        self.__host_count += count

    def get_host_count(self):
        """
        Get the total count of hosts retrieved so far.

        Returns:
            int: The total count of hosts.
        """
        params = GET_HOST_PARAMS.copy()

        # Get the hosts
        url = urljoin(self.url, "hosts/count")
        response = self.session.get(url, params=params, timeout=FLEETDM_SESSION_TIMEOUT)
        response.raise_for_status()

        # Return the hosts
        return response.json().get("count", 0)

    def get_hosts(self):
        """
        Retrieve a list of hosts from the FleetDM API.

        This method fetches hosts from the FleetDM API based on the current page and
        per_page settings. It updates the page number, checks if there are more pages,
        and updates the total host count.

        Returns:
            list: A list of hosts retrieved from the FleetDM API.
        """
        # Check if there is a next page
        if not self.next_page:
            LOGGER.info("No more hosts to get.")
            return []

        # Copy GET_HOST_PARAMS to avoid modifying the original
        params = GET_HOST_PARAMS.copy()
        params["page"] = self.__page
        params["per_page"] = self.__per_page
        LOGGER.debug(f"Params: {params}")

        # Get the hosts
        url = urljoin(self.url, "hosts")
        LOGGER.debug(f"Getting hosts from {url}.")

        LOGGER.info(f"Getting hosts from page {self.__page}.")
        response = self.session.get(url, params=params, timeout=FLEETDM_SESSION_TIMEOUT)
        response.raise_for_status()

        fleetdm_host_list = response.json().get("hosts", []) if response.content else []
        LOGGER.info(f"Got {len(fleetdm_host_list)} hosts.")
        # Update the page
        self.__update_page()
        self.__update_has_next(fleetdm_host_list)
        # Update the host count
        self.__update_host_count(len(fleetdm_host_list))
        # Return the hosts
        return fleetdm_host_list

    def get_return_hosts(self):
        """
        Get the total count of hosts retrieved so far.

        Returns:
            int: The total count of hosts.
        """
        return self.__host_count

    def has_next(self):
        """
        Check if there are more pages to fetch.

        Returns:
            bool: True if there are more pages, False otherwise.
        """
        return self.next_page

    def get_page(self):
        """
        Get the current page number.

        Returns:
            int: The current page number.
        """
        return self.__page
