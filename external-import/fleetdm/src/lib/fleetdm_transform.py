import logging
from urllib.parse import urljoin

from stix2 import (
    ExternalReference,
    Identity,
    IPv4Address,
    IPv6Address,
    MACAddress,
    Relationship,
    Software,
    Vulnerability,
)

from .fleetdm_constants import FLEETDM_SOFTWARE_STIX_MAP, FLEETDM_VULNERABILITY_STIX_MAP
from .fleetdm_utils import (
    cleanup_empty_string_in_dict,
    ip_type,
    parse_relationship_timestamp,
    parse_timestamp,
    remove_duplicates,
)

LOGGER = logging.getLogger(__name__)


class FleetDMSTIX:
    def __init__(self, base_url: str, data: dict):
        """
        Initialize the FleetDMSTIX class.

        Args:
            base_url (str): The base URL for FleetDM.
            data (dict): The data dictionary containing FleetDM data.
        """
        LOGGER.info(f"Transforming FleetDM data to STIX for {data.get('display_name')}")
        self._relationships = []
        self.base_url = base_url
        self.data = cleanup_empty_string_in_dict(data)
        self.stix = self.__get_stix()

    def __get_stix(self):
        """
        Generate STIX objects from FleetDM data.

        This method creates various STIX objects such as software, MAC address,
        IP addresses, and system information. It also manages relationships
        between these objects.

        Returns:
            list: A list of STIX objects.
        """
        stix_objects = []
        related_stix_objects = []
        self.__external_ref = self.__get_external_ref()
        software_id_list, software_stix_list = self.__get_software_list()
        related_stix_objects.extend(software_stix_list) if software_stix_list else None

        # Add Mac Address
        mac_address = self.__get_mac_address()
        related_stix_objects.append(mac_address.id) if mac_address else None

        # Add IP Address
        ip_address_id_list, ip_address_stix_list = self.__get_ipaddress()
        related_stix_objects.extend(ip_address_id_list) if ip_address_id_list else None

        # Get Custom System Object
        self.__system = self.__get_system(related_stix_objects)

        # Append all objects to the STIX Object List
        stix_objects.extend(software_stix_list)
        stix_objects.extend(self.__system)
        stix_objects.extend(ip_address_stix_list) if ip_address_stix_list else None
        stix_objects.append(mac_address) if mac_address else None
        # Add Relationships to the STIX Object List
        stix_objects.extend(self._relationships)

        return stix_objects

    def __get_ipaddress(self):
        """
        Retrieve and create IP address STIX objects from the FleetDM data.

        This method processes the 'public_ip' and 'primary_ip' fields from the data,
        determines their type (IPv4 or IPv6), and creates the appropriate STIX objects.

        Returns:
            tuple: A tuple containing two lists:
                - A list of unique IP address IDs.
                - A list of IP address STIX objects.
        """
        LOGGER.debug(f"Creating IP Address for {self.data.get('display_name')}")
        ip_address_list = []
        ip_address_keys = ["public_ip", "primary_ip"]
        for ip in ip_address_keys:
            ip_address = self.data.get(ip, None)
            ip_address_type = ip_type(ip_address)
            if ip_address_type == "ipv4-addr":
                ip_address = IPv4Address(value=ip_address)
                ip_address_list.append(ip_address)
            elif ip_address_type == "ipv6-addr":
                ip_address = IPv6Address(value=ip_address)
                ip_address_list.append(ip_address)
            else:
                continue
            LOGGER.debug(f"IP Address: {ip_address}")
        return remove_duplicates(data=ip_address_list)

    def __get_mac_address(self):
        """
        Retrieve and create MAC address STIX object from the FleetDM data.

        This method processes the 'primary_mac' field from the data
        and creates the appropriate STIX object.

        Returns:
            MACAddress: A STIX object representing the MAC address.
        """
        LOGGER.debug(f"Creating MAC Address for {self.data.get('display_name')}")
        mac_address = self.data.get("primary_mac", None)
        if mac_address:
            return MACAddress(value=mac_address)

    def __get_external_ref(self):
        """
        Create an External Reference STIX object.

        This method generates an External Reference object using the base URL
        and the host ID from the FleetDM data.

        Returns:
            ExternalReference: A STIX ExternalReference object.
        """
        LOGGER.debug(f"Creating External Reference for {self.data.get('display_name')}")
        external_reference_url = urljoin(self.base_url, f"hosts/{self.data.get('id')}")
        return ExternalReference(
            source_name="FleetDM",
            description=f'FleetDM Host Information for {self.data.get("display_name")}.',
            url=external_reference_url,
        )

    def __get_software_list(self):
        """
        Retrieve and create software STIX objects from the FleetDM data.

        This method processes the 'software' field from the data,
        creates the appropriate STIX objects, and removes duplicates.

        Returns:
            tuple: A tuple containing two lists:
                - A list of unique software IDs.
                - A list of software STIX objects.
        """
        LOGGER.debug(f"Creating Software List for {self.data.get('display_name')}")
        software_list = []
        for software in self.data.get("software", []):
            stix_objects = self.__get_software(software)
            software_list.extend(stix_objects)
        return remove_duplicates(data=software_list)

    def __get_software(self, software: dict):
        """
        Retrieve and create software STIX objects from the provided software dictionary.

        This method processes the software dictionary, checks for vulnerabilities,
        creates the appropriate STIX objects, and manages relationships between
        software and vulnerabilities.

        Args:
            software (dict): The dictionary containing software data.

        Returns:
            list: A list of software STIX objects.
        """
        LOGGER.debug(f"Creating Software Object for {software.get('name')}")
        vuln_ids = []  # Placeholder for vuln_ids
        vuln_list = []  # Placeholder for vuln_list
        stix_obj_list = []  # Placeholder for stix_obj_list

        # Cleanup empty strings in software dict
        software = cleanup_empty_string_in_dict(software)

        # Check if software has vulnerability and get vuln object
        if software.get("vulnerabilities", None):
            LOGGER.debug(f"Creating Vulnerability Object for {software.get('name')}")
            vuln_list = self.__get_vulnerability_list(
                software.get("vulnerabilities", None)
            )
            stix_obj_list.extend(vuln_list)

        # Create software object
        kwargs = self.__map_keys_to_stix(software, FLEETDM_SOFTWARE_STIX_MAP)

        if vuln_list:
            LOGGER.debug(f"Vuln List: {vuln_list}")
            vuln_ids, vuln_list = remove_duplicates(data=vuln_list)
            stix_object = Software(**kwargs)
            self.__create_relationships(
                source_ref=stix_object, target_ref_list=vuln_list
            )
        else:
            stix_object = Software(**kwargs)

        stix_obj_list.extend([stix_object])
        if stix_obj_list:
            return stix_obj_list
        else:
            return []

    def __create_relationships(
        self,
        source_ref,
        target_ref_list: list,
        relationship_type: str = "related-to",
        start_time=None,
        stop_time=None,
    ):
        """
        Create relationships between STIX objects.

        This method creates relationships between the source reference and a list of target references.
        It also manages optional start and stop times for the relationships.

        Args:
            source_ref: The source reference STIX object.
            target_ref_list (list): A list of target reference STIX objects.
            relationship_type (str, optional): The type of relationship. Default is "related-to".
            start_time (optional): The start time of the relationship.
            stop_time (optional): The stop time of the relationship.
        """
        for target_ref in target_ref_list:
            self.__create_relationship(
                source_ref=source_ref,
                target_ref=target_ref,
                relationship_type=relationship_type,
                start_time=start_time,
                stop_time=stop_time,
            )

    def __create_relationship(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str = "related-to",
        start_time=None,
        stop_time=None,
    ):
        """
        Create a relationship between two STIX objects.

        Args:
            source_ref (str): The source reference STIX object ID.
            target_ref (str): The target reference STIX object ID.
            relationship_type (str, optional): The type of relationship. Default is "related-to".
            start_time (optional): The start time of the relationship.
            stop_time (optional): The stop time of the relationship.
        """
        kwargs = {
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
        }
        if start_time:
            kwargs["start_time"] = parse_timestamp(start_time).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            )
        if stop_time:
            kwargs["stop_time"] = parse_relationship_timestamp(stop_time).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            )
        self._relationships.append(Relationship(**kwargs))

    def __map_keys_to_stix(self, data: dict, key_map: dict):
        """
        Map keys from the data dictionary to STIX format using a predefined key map.

        Args:
            data (dict): The dictionary containing the data.
            key_map (dict): The dictionary mapping source keys to STIX keys.

        Returns:
            dict: A dictionary with keys mapped to STIX format.
        """
        LOGGER.debug(
            f"Mapping keys to STIX for {data.get('display_name')} with {key_map}"
        )
        stix_obj = {}
        for key in key_map.keys():
            if key in data:
                stix_obj[key_map[key]] = data.get(key)
        return stix_obj

    def __get_vulnerability_list(self, vulnerabilities: list):
        """
        Retrieve and create vulnerability STIX objects from the provided vulnerabilities list.

        This method processes each vulnerability in the list, creates the appropriate STIX objects,
        and aggregates them into a list.

        Args:
            vulnerabilities (list): The list containing vulnerability data.

        Returns:
            list: A list of vulnerability STIX objects.
        """
        LOGGER.debug(f"Creating Vulnerability List for {self.data.get('display_name')}")
        vulnerability_list = []
        for vuln in vulnerabilities:
            vulnerability = self.__get_vulnerability(vuln)
            if vulnerability:
                vulnerability_list.append(vulnerability)
        return vulnerability_list

    def __get_vulnerability(self, vulnerability: dict):
        """
        Retrieve and create a vulnerability STIX object from the provided vulnerability dictionary.

        This method processes the vulnerability dictionary, adds external references,
        and timestamps, and creates the appropriate STIX object.

        Args:
            vulnerability (dict): The dictionary containing vulnerability data.

        Returns:
            Vulnerability: A STIX object representing the vulnerability.
        """
        LOGGER.debug(f"Creating Vulnerability Object for {vulnerability.get('cve')}")

        # Cleanup empty strings in vulnerability dict
        vulnerability = cleanup_empty_string_in_dict(vulnerability)

        # Create vulnerability object
        kwargs = self.__map_keys_to_stix(vulnerability, FLEETDM_VULNERABILITY_STIX_MAP)

        # Add external reference
        external_ref = self.__get_vulnerability_external_ref(vulnerability)
        if external_ref:
            kwargs["external_references"] = external_ref

        # Add created and modified timestamps
        if vulnerability.get("cve_published"):
            LOGGER.debug(
                f"Adding created and modified timestamps for {vulnerability.get('cve')}"
            )
            kwargs["created"] = vulnerability.get("cve_published")
            kwargs["modified"] = vulnerability.get("cve_published")

        if kwargs:
            return Vulnerability(**kwargs)
        else:
            return []

    def __get_vulnerability_external_ref(self, vulnerability: dict):
        """
        Retrieve and create external reference STIX objects from the provided vulnerability dictionary.

        This method processes the vulnerability dictionary and creates the appropriate external reference STIX objects.

        Args:
            vulnerability (dict): The dictionary containing vulnerability data.

        Returns:
            list: A list of STIX external reference objects.
        """
        external_ref = []
        if vulnerability.get("cve"):
            LOGGER.debug(f"Creating External Reference for {vulnerability.get('cve')}")
            external_ref.append(
                ExternalReference(
                    source_name="cve",
                    external_id=vulnerability.get("cve"),
                    description=f'Common Vulnerabilities and Exposures (CVE) for {vulnerability.get("cve")}.',
                    url=vulnerability.get("details_link"),
                )
            )
        return external_ref

    def __get_system(self, stix_object_list: list):
        """
        Retrieve and create a system STIX object from the FleetDM data.

        This method processes the FleetDM data to create a system STIX object and
        establishes relationships with other provided STIX objects.

        Args:
            stix_object_list (list): A list of related STIX objects.

        Returns:
            list: A list containing the system STIX object.
        """
        stix_objects = []  # Placeholder for stix_objects
        LOGGER.debug(f"Creating System Object for {self.data.get('display_name')}")
        kwargs = {
            "name": self.data.get("display_name"),
            "identity_class": "system",
            # TODO: Add description to Identity object
            # ,'description': self.data.get('description')
        }
        system = Identity(**kwargs)
        if stix_object_list:
            self.__create_relationships(
                source_ref=system,
                target_ref_list=stix_object_list,
                start_time=self.data.get("software_updated_at"),
                stop_time=self.data.get("software_updated_at"),
            )
        stix_objects.append(system)
        return stix_objects

    def get_stix_objects(self):
        """
        Retrieve the STIX objects generated from the FleetDM data.

        Returns:
            list: A list of STIX objects.
        """
        return self.stix
