import os
import sys
import time
from datetime import datetime

import stix2

from lib.external_import import ExternalImportConnector
from lib.fleetdm import FleetDMHostList
from lib.fleetdm_transform import FleetDMSTIX
from lib.fleetdm_utils import remove_duplicates, divide_and_round_up


class CustomConnector(ExternalImportConnector):
    def __init__(self):
        """Initialization of the connector

        Note that additional attributes for the connector can be set after the super() call.

        Standardized way to grab attributes from environment variables is as follows:

        >>>         ...
        >>>         super().__init__()
        >>>         self.my_attribute = os.environ.get("MY_ATTRIBUTE", "INFO")

        This will make use of the `os.environ.get` method to grab the environment variable and set a default value (in the example "INFO") if it is not set.
        Additional tunning can be made to the connector by adding additional environment variables.

        Raising ValueErrors or similar might be useful for tracking down issues with the connector initialization.
        """
        super().__init__()
        self.base_url = os.environ.get("FLEETDM_BASE_URL", False)
        self.api_key = os.environ.get("FLEETDM_API_KEY", False)
        self.per_page = int(os.environ.get("FLEETDM_PER_PAGE", 100))

        if not self.base_url or not self.api_key:
            raise ValueError(f"FleetDM base URL ({self.base_url}) and API key ({self.api_key}) are required.")

    def _collect_intelligence(self, timestamp: int):
        """Collects intelligence from channels.

        Returns:
            stix_objects: A list of STIX2 objects.
        """
        self.helper.connector_logger.debug(f"{self.helper.connect_name} connector is starting the collection of objects...")

        now = datetime.utcfromtimestamp(timestamp)
        fdm = FleetDMHostList(base_url=self.base_url, api_key=self.api_key, per_page=self.per_page)

        host_count = fdm.get_host_count()
        self.helper.connector_logger.info(f'{host_count} hosts found in FleetDM.')

        pages = divide_and_round_up(host_count, self.per_page)
        self.helper.connector_logger.info(f'Estimated number of pages: {pages}')

        work_id_list = self._process_pages(fdm, pages, now)

        self.helper.connector_logger.info(f"{self.helper.connect_name} connector has finished the collection of objects, Total Hosts Returned: {fdm.get_return_hosts()}.")
        return None

    def _process_pages(self, fdm, pages, now):
        """Process each page of hosts and collect STIX objects.

        Args:
            fdm: The FleetDMHostList instance.
            pages (int): The total number of pages.
            now (datetime): The current timestamp.

        Returns:
            list: A list of work IDs.
        """
        work_id_list = []

        for page_number in range(pages):
            stix_objects = []
            friendly_name = f'{self.helper.connect_name}, page ({fdm.get_page()}/{pages}), run @ {now.strftime("%Y-%m-%d %H:%M:%S")}'
            work_id = self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)
            work_id_list.append(work_id)

            host_list = fdm.get_hosts()

            for host in host_list:
                stix_obj = FleetDMSTIX(base_url=self.base_url, data=host)
                stix_objects.extend(stix_obj.get_stix_objects())

            stix_objects_ids, stix_objects = remove_duplicates(data=stix_objects)
            self.helper.connector_logger.info(f"{len(stix_objects_ids)} STIX2 objects have been compiled by {self.helper.connect_name} connector.")

            self._send_stix_bundle(stix_objects, work_id)

        return work_id_list

    def _send_stix_bundle(self, stix_objects, work_id):
        """Send STIX objects as a bundle to OpenCTI.

        Args:
            stix_objects (list): A list of STIX objects.
            work_id (str): The work ID.
        """
        bundle = stix2.Bundle(objects=stix_objects, allow_custom=True).serialize()
        # write to file
        with open('test/stix_bundle.json', 'w') as f:
            f.write(bundle)
        self.helper.send_stix2_bundle(bundle, update=self.update_existing_data, work_id=work_id)
        self.helper.connector_logger.info(f"STIX objects have been sent to OpenCTI.")

if __name__ == "__main__":
    try:
        connector = CustomConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
