from pathlib import Path
from unittest.mock import mock_open, patch

import pytest
import yaml

from installation_assistant.managers.config_manager import ConfigInvalidDataError, ConfigManager

CORRECT_CONFIG = {
    "nodes": {
        "indexer": [{"name": "node-1", "ip": "127.0.0.1"}, {"name": "node-2", "ip": "127.0.0.2"}],
        "server": [
            {
                "name": "node-server",
                "ip": "192.168.56.101",
            },
        ],
        "dashboard": [
            {
                "name": "node-3",
                "ip": "127.0.0.1",
            },
            {"name": "node-4", "ip": "127.0.0.3"},
        ],
    }
}

INCORRECT_CONFIG_NODES_NAME = {
    "indexer": [
        {"name": "node-1", "ip": "127.0.0.1"},
    ],
}

INCORRECT_CONFIG_NODE_TYPE = {
    "nodes": {
        "indexer": {"name": "node-1", "ip": "127.0.0.1"},
    }
}

INCORRECT_CONFIG_NODE = {
    "nodes": {
        "asado": [
            {"name": "node-1", "ip": "127.0.0.1"},
        ],
        "dashboard": [
            {
                "name": "node-3",
                "ip": "127.0.0.1",
            },
        ],
    }
}

INCOMPLETE_CONFIG_NODE_FIELD = {
    "nodes": {
        "dashboard": [
            {
                "ip": "127.0.0.1",
            },
        ],
    }
}
INCORRECT_CONFIG_DUPLICATED_IP = {
    "nodes": {
        "indexer": [{"name": "node-1", "ip": "127.0.0.1"}, {"name": "node-2", "ip": "127.0.0.1"}],
        "dashboard": [
            {
                "name": "node-3",
                "ip": "127.0.0.1",
            },
        ],
    }
}

INCORRECT_CONFIG_DUPLICATED_NAME = {
    "nodes": {
        "indexer": [
            {"name": "node-1", "ip": "127.0.0.1"},
        ],
        "dashboard": [
            {
                "name": "node-1",
                "ip": "127.0.0.2",
            },
        ],
    }
}


@pytest.fixture
def valid_config_file():
    with patch(
        "installation_assistant.managers.config_manager.open", mock_open(read_data=yaml.dump(CORRECT_CONFIG))
    ) as mock_file:
        yield mock_file


@pytest.fixture(autouse=True)
def mock_path_exists():
    with patch("pathlib.Path.exists", return_value=True) as mock_exists:
        yield mock_exists


@pytest.fixture(autouse=True)
def mock_path_is_file():
    with patch("pathlib.Path.is_file", return_value=True) as mock_is_file:
        yield mock_is_file


@pytest.fixture
def valid_config_manager(valid_config_file, mock_path_exists, mock_path_is_file):
    config_manager = ConfigManager(config_file=Path("tests_config.yaml"))
    return config_manager


def test_config_manager_correct_initialize(mock_path_is_file, mock_path_exists, valid_config_file):
    config_manager = ConfigManager(config_file=Path("tests_config.yaml"))

    assert config_manager.config_file == Path("tests_config.yaml")
    assert config_manager.config_file_data == CORRECT_CONFIG["nodes"]
    mock_path_exists.assert_called_once()
    mock_path_is_file.assert_called_once()


@patch("pathlib.Path.exists", return_value=False)
def test_config_manager_without_existing_file(mock_exists):
    with pytest.raises(FileNotFoundError) as excinfo:
        ConfigManager(config_file=Path("tests_config.yaml"))
    assert str(excinfo.value) == "Config file 'tests_config.yaml' does not exist."
    mock_exists.assert_called_once()


@patch("pathlib.Path.is_file", return_value=False)
def test_config_manager_without_correct_file(mock_is_file, mock_path_exists):
    with pytest.raises(IsADirectoryError) as excinfo:
        ConfigManager(config_file=Path("tests_config.yaml"))
    assert str(excinfo.value) == "Config file 'tests_config.yaml' is not a file."
    mock_is_file.assert_called_once()


@patch("yaml.safe_load", side_effect=yaml.YAMLError("Error parsing YAML"))
def test_config_manager_with_invalid_yaml(mock_safe_load, valid_config_file):
    with pytest.raises(ValueError) as excinfo:
        ConfigManager(config_file=Path("tests_config.yaml"))
    assert str(excinfo.value) == "Invalid YAML format: Error parsing YAML"
    mock_safe_load.assert_called_once()

    mock_safe_load.assert_called_once()


@pytest.mark.parametrize(
    "config_data, expected_error",
    [
        (INCORRECT_CONFIG_NODES_NAME, "You must define 'nodes' as the first section in the YAML file."),
        (INCORRECT_CONFIG_NODE_TYPE, "The 'indexer' section must be a list of nodes."),
        (
            INCORRECT_CONFIG_NODE,
            "Invalid node section 'asado'. Permitted sections are: 'indexer', 'server', 'dashboard'.",
        ),
        (INCOMPLETE_CONFIG_NODE_FIELD, "Each node in 'dashboard' section must have 'name' and 'ip' entries."),
        (INCORRECT_CONFIG_DUPLICATED_IP, "The IP '127.0.0.1' is duplicated in the 'indexer' section."),
        (INCORRECT_CONFIG_DUPLICATED_NAME, "The name 'node-1' is duplicated in different sections."),
    ],
)
def test_config_manager_incorrect_initialize(config_data, expected_error):
    with patch("installation_assistant.managers.config_manager.open", mock_open(read_data=yaml.dump(config_data))):
        with pytest.raises(ConfigInvalidDataError) as excinfo:
            ConfigManager(config_file=Path("tests_config.yaml"))
        assert str(excinfo.value) == expected_error


def test_get_indexer_nodes(valid_config_manager):
    nodes = valid_config_manager.indexer_nodes
    assert len(nodes) == 2
    assert nodes[0]["name"] == "node-1"
    assert nodes[0]["ip"] == "127.0.0.1"
    assert nodes[1]["name"] == "node-2"
    assert nodes[1]["ip"] == "127.0.0.2"


def test_get_server_nodes(valid_config_manager):
    nodes = valid_config_manager.server_nodes
    assert len(nodes) == 1
    assert nodes[0]["name"] == "node-server"
    assert nodes[0]["ip"] == "192.168.56.101"


def test_get_dashboard_nodes(valid_config_manager):
    nodes = valid_config_manager.dashboard_nodes
    assert len(nodes) == 2
    assert nodes[0]["name"] == "node-3"
    assert nodes[0]["ip"] == "127.0.0.1"
    assert nodes[1]["name"] == "node-4"
    assert nodes[1]["ip"] == "127.0.0.3"


def test_get_component_nodes_from_empty_node_config(mock_path_exists, mock_path_is_file):
    test_config = {"nodes": {}}

    with patch("installation_assistant.managers.config_manager.open", mock_open(read_data=yaml.dump(test_config))):
        config_manager = ConfigManager(config_file=Path("tests_config.yaml"))
        assert config_manager.indexer_nodes == []
        assert config_manager.server_nodes == []
        assert config_manager.dashboard_nodes == []


@pytest.mark.parametrize(
    "node_type, name, ip, expected_node",
    [
        ("indexer", "node-1", None, {"name": "node-1", "ip": "127.0.0.1"}),
        ("indexer", "node-2", None, {"name": "node-2", "ip": "127.0.0.2"}),
        ("indexer", None, "127.0.0.1", {"name": "node-1", "ip": "127.0.0.1"}),
        ("indexer", "node-1", "127.0.0.2", None),
        ("server", "node-server", None, {"name": "node-server", "ip": "192.168.56.101"}),
        ("server", None, "192.168.56.101", {"name": "node-server", "ip": "192.168.56.101"}),
        ("server", "node-server", "192.168.56.101", {"name": "node-server", "ip": "192.168.56.101"}),
        ("dashboard", "node-3", None, {"name": "node-3", "ip": "127.0.0.1"}),
        ("dashboard", None, None, None),
        ("dashboard", "node-5", "fake_ip", None),
    ],
)
def test_get_node_from_key(node_type, ip, name, expected_node, valid_config_manager):
    node = valid_config_manager._get_component_node_from_key(node_type, name, ip)

    assert node == expected_node


def test_get_node_from_key_with_invalid_node_type(valid_config_manager):
    with pytest.raises(ValueError) as excinfo:
        valid_config_manager._get_component_node_from_key("invalid_type", "node-1", None)
    assert (
        str(excinfo.value)
        == "Invalid component 'invalid_type'. Permitted components are: 'indexer', 'server', 'dashboard'."
    )


CORRECT_CONFIG = {
    "nodes": {
        "indexer": [{"name": "node-1", "ip": "127.0.0.1"}, {"name": "node-2", "ip": "127.0.0.2"}],
        "server": [
            {
                "name": "node-server",
                "ip": "192.168.56.101",
            },
        ],
        "dashboard": [
            {
                "name": "node-3",
                "ip": "127.0.0.1",
            },
            {"name": "node-4", "ip": "127.0.0.3"},
        ],
    }
}


@pytest.mark.parametrize(
    "name, ip, expected_node",
    [
        ("node-1", None, {"name": "node-1", "ip": "127.0.0.1"}),
        ("node-2", None, {"name": "node-2", "ip": "127.0.0.2"}),
        (None, "127.0.0.1", {"name": "node-1", "ip": "127.0.0.1"}),
        ("node-2", "127.0.0.2", {"name": "node-2", "ip": "127.0.0.2"}),
    ],
)
def test_get_indexer_node_from_key(name, ip, expected_node, valid_config_manager):
    node = valid_config_manager.get_indexer_node_from_key(name=name, ip=ip)
    assert node == expected_node


@pytest.mark.parametrize(
    "name, ip, expected_node",
    [
        ("node-server", None, {"name": "node-server", "ip": "192.168.56.101"}),
        (None, "192.168.56.101", {"name": "node-server", "ip": "192.168.56.101"}),
        ("node-server", "bad_ip", None),
    ],
)
def test_get_server_node_from_key(name, ip, expected_node, valid_config_manager):
    node = valid_config_manager.get_server_node_from_key(name=name, ip=ip)
    assert node == expected_node


@pytest.mark.parametrize(
    "name, ip, expected_node",
    [
        ("node-3", None, {"name": "node-3", "ip": "127.0.0.1"}),
        (None, "127.0.0.3", {"name": "node-4", "ip": "127.0.0.3"}),
        ("node-4", "bad-ip", None),
    ],
)
def test_get_dashboard_node_from_key(name, ip, expected_node, valid_config_manager):
    node = valid_config_manager.get_dashboard_node_from_key(name=name, ip=ip)
    assert node == expected_node
