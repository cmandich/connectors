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
        self.base_url = os.environ.get("FLEETDM_BASE_URL", None)
        self.api_key = os.environ.get("FLEETDM_API_KEY", None)
        self.per_page = int(os.environ.get("FLEETDM_PER_PAGE", 100))

    def _collect_intelligence(self, timestamp: int) -> []:
        """Collects intelligence from channels

        Add your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )

        now = datetime.utcfromtimestamp(timestamp)
        fdm = FleetDMHostList(base_url=self.base_url, api_key=self.api_key, per_page=self.per_page)

        # Get the total number of hosts
        host_count = fdm.get_host_count()
        self.helper.log_info(f'{host_count} hosts found in FleetDM.')

        # Get estimated number of pages
        pages = divide_and_round_up(host_count, self.per_page)
        self.helper.log_info(f'Estimated number of pages: {pages}')

        work_id_list = [] # List to store work IDs

        for page_number in range(pages):
            # while fdm.has_next_page():
            stix_objects = []
            friendly_name = f'{self.helper.connect_name}, page ({fdm.get_page()}/{pages}), run @ {now.strftime("%Y-%m-%d %H:%M:%S")}'
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            work_id_list.append(work_id)

            # Get all hosts
            host_list = fdm.get_hosts()

            # TODO: Add Multi-threading here?
            for i in host_list:
                stix_objects.extend(FleetDMSTIX(base_url=self.base_url, data=i).get_stix_objects())

            stix_objects_ids, stix_objects = remove_duplicates(data = stix_objects)
            self.helper.log_info(
                        f"{len(stix_objects_ids)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
                    )

            bundle = stix2.Bundle(objects=stix_objects, allow_custom=True).serialize()

            self.helper.log_info(f"Sending {len(stix_objects_ids)} STIX objects to OpenCTI...")
            self.helper.send_stix2_bundle(
                bundle,
                update=self.update_existing_data,
                work_id=work_id,
            )
            self.helper.log_info(f"STIX objects have been sent to OpenCTI.")

        # for work_id in work_id_list:
        #     self.helper.api.work.to_processed(work_id, f"{self.helper.connect_name} connector has finished the collection of objects.")

        self.helper.log_info(f"{self.helper.connect_name} connector has finished the collection of objects, Total Hosts Returned: {fdm.get_return_hosts()}.")
        return None

if __name__ == "__main__":
    try:
        connector = CustomConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
