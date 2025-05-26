from pathlib import Path

import yaml

from utils import Logger

logger = Logger("ConfigManager")


class ConfigInvalidDataError(Exception):
    """Custom exception for invalid configuration data."""

    pass


class ConfigManager:
    def __init__(self, config_file: Path):
        """
        Initialize the ConfigManager instance.
        This class is responsible for managing the configuration file for the Wazuh installation assistant.
        It validates the configuration file and provides methods to access the configuration data.
        Args:
            config_file (Path): Path to the configuration file.

        Attributes:
            config_file (Path): Stores the path to the configuration file.
            permitted_components (list): List of permitted components ("indexer", "server", "dashboard").
            config_file_data (dict): Parsed and validated configuration data for nodes.
        """

        self.config_file = config_file
        self.permitted_components = ["indexer", "server", "dashboard"]
        try:
            temporal_config_data = self._validate_config_file()
            self._validate_config_data(temporal_config_data)
            self.config_file_data = temporal_config_data["nodes"]
        except Exception as e:
            logger.error(f"Failed to validate config file: {e}")
            raise

    @property
    def indexer_nodes(self) -> list:
        """
        Retrieve the list of indexer nodes from the configuration file.

        Returns:
            list: A list of indexer nodes if present in the configuration file;
                  otherwise, an empty list.
        """

        if self.config_file_data.get("indexer"):
            return self.config_file_data["indexer"]

        return []

    @property
    def server_nodes(self) -> list:
        """
        Retrieve the list of server nodes from the configuration file.

        Returns:
            list: A list of server nodes if present in the configuration file;
                  otherwise, an empty list.
        """

        if self.config_file_data.get("server"):
            return self.config_file_data["server"]

        return []

    @property
    def dashboard_nodes(self) -> list:
        """
        Retrieve the list of dashboard nodes from the configuration file.

        Returns:
            list: A list of dashboard nodes if present in the configuration file;
                  otherwise, an empty list.
        """

        if self.config_file_data.get("dashboard"):
            return self.config_file_data["dashboard"]

        return []

    def _validate_config_file(self) -> dict:
        """
        Validates the configuration file by checking its existence, type, and content.

        This method performs the following checks:
        1. Ensures the configuration file exists.
        2. Verifies that the configuration file is not a directory.
        3. Reads and parses the configuration file as YAML.

        Returns:
            dict: The parsed configuration data from the YAML file. It may be invalid data, but the file is valid.
        """

        logger.debug(f"Reading config file: {self.config_file}")

        if not self.config_file.exists():
            raise FileNotFoundError(f"Config file '{self.config_file}' does not exist.") from None
        if not self.config_file.is_file():
            raise IsADirectoryError(f"Config file '{self.config_file}' is not a file.") from None

        with open(self.config_file) as file:
            try:
                config_data = yaml.safe_load(file)
            except Exception as e:
                raise ValueError(f"Invalid YAML format: {e}") from None

        logger.debug(f"Validating config file data: {self.config_file}")
        return config_data

    def _validate_config_data(self, data: dict) -> None:
        """
        Validates the configuration data provided in the form of a dictionary.

        This method ensures that the configuration data adheres to the expected structure
        and contains valid entries. It checks for the presence of required sections, validates
        the format of each section. It check:
        1. The presence of the "nodes" section.
        2. The type of each section (must be a list).
        3. The validity of each section name (must be one of the permitted components).
        4. The presence of "name" and "ip" entries in each node.
        5. The uniqueness of "name" entries across different sections.
        6. The uniqueness of "ip" entries within the same section.

        Args:
            data (dict): The configuration data to validate. It must contain a "nodes" section
                         with valid entries.
        """

        nodes = data.get("nodes")

        if nodes is None:
            raise ConfigInvalidDataError("You must define 'nodes' as the first section in the YAML file.")

        all_names = set()

        for subkey, entries in nodes.items():
            if not isinstance(entries, list):
                raise ConfigInvalidDataError(f"The '{subkey}' section must be a list of nodes.")
            if subkey not in self.permitted_components:
                raise ConfigInvalidDataError(
                    f"Invalid node section '{subkey}'. Permitted sections are: '{"', '".join(self.permitted_components)}'."
                )

            seen_ips = set()

            for item in entries:
                name = item.get("name")
                ip = item.get("ip")

                if not name or not ip:
                    raise ConfigInvalidDataError(f"Each node in '{subkey}' section must have 'name' and 'ip' entries.")
                if name in all_names:
                    raise ConfigInvalidDataError(f"The name '{name}' is duplicated in different sections.")
                if ip in seen_ips:
                    raise ConfigInvalidDataError(f"The IP '{ip}' is duplicated in the '{subkey}' section.")

                all_names.add(name)
                seen_ips.add(ip)

    def _get_component_node_from_key(
        self, component: str, name: str | None = None, ip: str | None = None
    ) -> dict | None:
        """
        Retrieve a component node dictionary based on the specified key attributes.

        Args:
            component (str): The type of component to search for. Must be one of the permitted components.
            name (str | None, optional): The name of the node to search for. Defaults to None.
            ip (str | None, optional): The IP address of the node to search for. Defaults to None.

        Returns:
            dict | None: The matching node dictionary if found, otherwise None.

        Raises:
            ValueError: If the specified component is not in the list of permitted components.

        Notes:
            - The method searches for a node that matches either the `name`, `ip`, or both.
            - If both `name` and `ip` are provided, the node must match both attributes.
            - If only one of `name` or `ip` is provided, the method searches for a node matching that attribute.
        """

        if component not in self.permitted_components:
            raise ValueError(
                f"Invalid component '{component}'. Permitted components are: '{"', '".join(self.permitted_components)}'."
            )

        for node in getattr(self, f"{component}_nodes"):
            if (
                (not name and node.get("ip") == ip)
                or (not ip and node.get("name") == name)
                or (node.get("name") == name and node.get("ip") == ip)
            ):
                return node
        return None

    def get_indexer_node_from_key(self, name: str | None = None, ip: str | None = None) -> dict | None:
        """
        Retrieve an indexer node's details by its name or IP address.

        This method searches for an indexer node within the system configuration
        using either its name or IP address as a key. If a matching node is found,
        its details are returned as a dictionary. If no match is found, None is returned.

        Args:
            name (str | None): The name of the indexer node to search for. Defaults to None.
            ip (str | None): The IP address of the indexer node to search for. Defaults to None.

        Returns:
            dict | None: A dictionary containing the details of the matching indexer node,
            or None if no match is found.
        """
        return self._get_component_node_from_key("indexer", name, ip)

    def get_server_node_from_key(self, name: str | None = None, ip: str | None = None) -> dict | None:
        """
        Retrieve a server node's details by its name or IP address.

        This method searches for a server node within the system configuration
        using either its name or IP address as a key. If a matching node is found,
        its details are returned as a dictionary. If no match is found, None is returned.

        Args:
            name (str | None): The name of the server node to search for. Defaults to None.
            ip (str | None): The IP address of the server node to search for. Defaults to None.

        Returns:
            dict | None: A dictionary containing the details of the matching server node,
            or None if no match is found.
        """
        return self._get_component_node_from_key("server", name, ip)

    def get_dashboard_node_from_key(self, name: str | None = None, ip: str | None = None) -> dict | None:
        """
        Retrieve a dashboard node's details by its name or IP address.

        This method searches for a dashboard node within the system configuration
        using either its name or IP address as a key. If a matching node is found,
        its details are returned as a dictionary. If no match is found, None is returned.

        Args:
            name (str | None): The name of the dashboard node to search for. Defaults to None.
            ip (str | None): The IP address of the dashboard node to search for. Defaults to None.

        Returns:
            dict | None: A dictionary containing the details of the matching dashboard node,
            or None if no match is found.
        """
        return self._get_component_node_from_key("dashboard", name, ip)
