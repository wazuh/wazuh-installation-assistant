from enum import StrEnum, auto


class Component(StrEnum):
    WAZUH_INDEXER = auto()
    WAZUH_SERVER = auto()
    WAZUH_DASHBOARD = auto()
    ALL = auto()
