from enum import StrEnum, auto


class SupportedDistribution(StrEnum):
    AMZN_2023 = auto()
    AMZN_2 = auto()
    CENTOS_8 = auto()
    CENTOS_9 = auto()
    RHEL_7 = auto()
    RHEL_8 = auto()
    RHEL_9 = auto()
    UBUNTU_16_04 = auto()
    UBUNTU_18_04 = auto()
    UBUNTU_20_04 = auto()
    UBUNTU_22_04 = auto()
    UBUNTU_24_04 = auto()
