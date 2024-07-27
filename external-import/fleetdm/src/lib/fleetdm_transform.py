import logging
from urllib.parse import urljoin
from stix2 import ExternalReference, Identity, IPv4Address, IPv6Address, MACAddress, Relationship, Software, Vulnerability
from pycti import Vulnerability as pycti_vulnerability, Identity as pycti_identity

from .fleetdm_constants import FLEETDM_SOFTWARE_STIX_MAP, FLEETDM_VULNERABILITY_STIX_MAP
from .fleetdm_utils import cleanup_empty_strings, ip_type, parse_relationship_timestamp, parse_timestamp, remove_duplicates, generate_id

LOGGER = logging.getLogger(__name__)

class FleetDMSTIX:
    def __init__(self, base_url: str, data: dict):
        """
        Initialize the FleetDMSTIX class.

        Args:
            base_url (str): The base URL for FleetDM.
            data (dict): The data dictionary containing FleetDM data.
        """
        LOGGER.debug(f"Transforming FleetDM data to STIX for {data.get('display_name')}")
        self._relationships = []
        self.base_url = base_url
        self.data = cleanup_empty_strings(data)
        self.stix = self.__get_stix_objects()

    def __get_stix_objects(self):
        """
        Generate STIX objects from FleetDM data.

        This method creates various STIX objects such as software, MAC address,
        IP addresses, and system information. It also manages relationships
        between these objects.

        Returns:
            list: A list of STIX objects.
        """
        stix_objects = []
        related_stix_ids = []

        self.__external_ref = self.__create_external_ref()
        software_ids, software_objects = self.__create_software_objects()
        related_stix_ids.extend(software_ids)

        mac_address = self.__create_mac_address()
        if mac_address:
            related_stix_ids.append(mac_address.id)
            stix_objects.append(mac_address)

        ip_address_ids, ip_address_objects = self.__create_ip_addresses()
        related_stix_ids.extend(ip_address_ids)
        stix_objects.extend(ip_address_objects)

        system_objects = self.__create_system_objects(related_stix_ids)
        stix_objects.extend(system_objects)

        stix_objects.extend(software_objects)
        stix_objects.extend(self._relationships)

        return stix_objects

    def __create_ip_addresses(self):
        """
        Retrieve and create IP address STIX objects from the FleetDM data.

        Returns:
            tuple: A tuple containing two lists:
                - A list of unique IP address IDs.
                - A list of IP address STIX objects.
        """
        LOGGER.debug(f"Creating IP Addresses for {self.data.get('display_name')}")
        ip_addresses = []
        for key in ["public_ip", "primary_ip"]:
            ip_address = self.data.get(key)
            if ip_address:
                ip_type_func = IPv4Address if ip_type(ip_address) == "ipv4-addr" else IPv6Address
                ip_addresses.append(ip_type_func(value=ip_address))

        return remove_duplicates(data=ip_addresses)

    def __create_mac_address(self):
        """
        Retrieve and create MAC address STIX object from the FleetDM data.

        Returns:
            MACAddress: A STIX object representing the MAC address.
        """
        LOGGER.debug(f"Creating MAC Address for {self.data.get('display_name')}")
        mac_address = self.data.get("primary_mac")
        return MACAddress(value=mac_address) if mac_address else None

    def __create_external_ref(self):
        """
        Create an External Reference STIX object.

        Returns:
            ExternalReference: A STIX ExternalReference object.
        """
        LOGGER.debug(f"Creating External Reference for {self.data.get('display_name')}")
        url = urljoin(self.base_url, f"hosts/{self.data.get('id')}")
        return ExternalReference(
            source_name="FleetDM",
            description=f'FleetDM Host Information for {self.data.get("display_name")}.',
            url=url,
        )

    def __create_software_objects(self):
        """
        Retrieve and create software STIX objects from the FleetDM data.

        Returns:
            tuple: A tuple containing two lists:
                - A list of unique software IDs.
                - A list of software STIX objects.
        """
        LOGGER.debug(f"Creating Software Objects for {self.data.get('display_name')}")
        software_list = [self.__create_software(software) for software in self.data.get("software", [])]
        return remove_duplicates(data=[item for sublist in software_list for item in sublist])

    def __create_software(self, software: dict):
        """
        Create software STIX objects and related vulnerabilities.

        Args:
            software (dict): The dictionary containing software data.

        Returns:
            list: A list of software and related vulnerability STIX objects.
        """
        LOGGER.debug(f"Creating Software Object for {software.get('name')}")
        software = cleanup_empty_strings(software)
        stix_objects = []
        vuln_objects = []

        vulnerabilities = software.get("vulnerabilities")
        if vulnerabilities:
            vuln_objects = self.__create_vulnerability_objects(vulnerabilities)
            stix_objects.extend(vuln_objects)

        kwargs = self.__map_keys_to_stix(software, FLEETDM_SOFTWARE_STIX_MAP)
        kwargs['id'] = generate_id(prefix='software', data=kwargs)

        software_obj = Software(**kwargs)
        stix_objects.append(software_obj)

        if vuln_objects:
            vuln_ids = [vuln.id for vuln in vuln_objects]
            self.__create_relationships(software_obj.id, vuln_ids)

        return stix_objects

    def __create_relationships(self, source_ref, target_refs, relationship_type="related-to", start_time=None, stop_time=None):
        """
        Create relationships between STIX objects.

        Args:
            source_ref: The source reference STIX object.
            target_refs (list): A list of target reference STIX objects.
            relationship_type (str, optional): The type of relationship. Default is "related-to".
            start_time (optional): The start time of the relationship.
            stop_time (optional): The stop time of the relationship.
        """
        for target_ref in target_refs:
            self.__create_relationship(source_ref, target_ref, relationship_type, start_time, stop_time)

    def __create_relationship(self, source_ref, target_ref, relationship_type="related-to", start_time=None, stop_time=None):
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
            kwargs["start_time"] = parse_timestamp(start_time).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if stop_time:
            kwargs["stop_time"] = parse_relationship_timestamp(stop_time).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
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
        LOGGER.debug(f"Mapping keys to STIX for {data.get('display_name')}")
        return {stix_key: data[key] for key, stix_key in key_map.items() if key in data}

    def __create_vulnerability_objects(self, vulnerabilities: list):
        """
        Retrieve and create vulnerability STIX objects from the provided vulnerabilities list.

        Args:
            vulnerabilities (list): The list containing vulnerability data.

        Returns:
            list: A list of vulnerability STIX objects.
        """
        LOGGER.debug(f"Creating Vulnerability Objects for {self.data.get('display_name')}")
        vuln_list = [self.__create_vulnerability(vuln) for vuln in vulnerabilities if vuln]
        # Remove any None values from the list
        return [vuln for vuln in vuln_list if vuln]

    def __create_vulnerability(self, vulnerability: dict):
        """
        Retrieve and create a vulnerability STIX object from the provided vulnerability dictionary.

        Args:
            vulnerability (dict): The dictionary containing vulnerability data.

        Returns:
            Vulnerability: A STIX object representing the vulnerability.
        """
        LOGGER.debug(f"Creating Vulnerability Object for {vulnerability.get('cve')}")
        vulnerability = cleanup_empty_strings(vulnerability)
        kwargs = self.__map_keys_to_stix(vulnerability, FLEETDM_VULNERABILITY_STIX_MAP)

        if "name" in kwargs:
            kwargs['id'] = pycti_vulnerability.generate_id(kwargs.get("name"))
        external_ref = self.__create_vulnerability_external_ref(vulnerability)
        if external_ref:
            kwargs["external_references"] = external_ref

        if vulnerability.get("cve_published"):
            kwargs["created"] = vulnerability.get("cve_published")
            kwargs["modified"] = vulnerability.get("cve_published")

        return Vulnerability(**kwargs) if kwargs else None

    def __create_vulnerability_external_ref(self, vulnerability: dict):
        """
        Retrieve and create external reference STIX objects from the provided vulnerability dictionary.

        Args:
            vulnerability (dict): The dictionary containing vulnerability data.

        Returns:
            list: A list of STIX external reference objects.
        """
        if "cve" in vulnerability:
            LOGGER.debug(f"Creating External Reference for {vulnerability.get('cve')}")
            return [ExternalReference(
                source_name="cve",
                external_id=vulnerability.get("cve"),
                description=f'Common Vulnerabilities and Exposures (CVE) for {vulnerability.get("cve")}.',
                url=vulnerability.get("details_link"),
            )]
        return []

    def __create_system_objects(self, related_stix_ids):
        """
        Retrieve and create a system STIX object from the FleetDM data.

        Args:
            related_stix_ids (list): A list of related STIX object IDs.

        Returns:
            list: A list containing the system STIX object.
        """
        LOGGER.debug(f"Creating System Object for {self.data.get('display_name')}")
        kwargs = {
            "id": pycti_identity.generate_id(
                name=self.data.get("display_name"),
                identity_class="system"
            ),
            "name": self.data.get("display_name"),
            "identity_class": "system",
        }
        # TODO: Add System description.
        system = Identity(**kwargs)
        if related_stix_ids:
            self.__create_relationships(
                source_ref=system.id,
                target_refs=related_stix_ids,
                start_time=self.data.get("software_updated_at"),
                stop_time=self.data.get("software_updated_at"),
            )
        return [system]

    def get_stix_objects(self):
        """
        Retrieve the STIX objects generated from the FleetDM data.

        Returns:
            list: A list of STIX objects.
        """
        return self.stix
