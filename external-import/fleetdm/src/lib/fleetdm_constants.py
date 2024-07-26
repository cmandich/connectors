BASE_URI_PATH = "/api/v1/fleet/"  # Base URI path for FleetDM API
FLEETDM_SESSION_TIMEOUT = 600  # Session timeout duration in seconds
GET_HOST_PARAMS = {
    "populate_policies": True,  # Whether to populate policies data
    "populate_software": True,  # Whether to populate software data
    "order_key": "created_at",  # Field to order the results by
    "order_direction": "asc",  # Direction of the ordering (ascending)
}

FLEETDM_SOFTWARE_STIX_MAP = {
    "name": "name",  # Map FleetDM 'name' to STIX 'name'
    "version": "version",  # Map FleetDM 'version' to STIX 'version'
    "generated_cpe": "cpe",  # Map FleetDM 'generated_cpe' to STIX 'cpe'
    "vendor": "vendor",  # Map FleetDM 'vendor' to STIX 'vendor'
}

FLEETDM_VULNERABILITY_STIX_MAP = {
    "cve": "name",  # Map FleetDM 'cve' to STIX 'name'
    "cve_description": "description",  # Map FleetDM 'cve_description' to STIX 'description'
}
