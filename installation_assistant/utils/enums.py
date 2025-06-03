from enum import StrEnum, auto


class PackageManager(StrEnum):
    YUM = auto()
    APT = auto()


class PackageType(StrEnum):
    RPM = auto()
    DEB = auto()


class ComponentArch(StrEnum):
    AMD64 = auto()
    X86_64 = auto()
    ARM64 = auto()
    AARCH64 = auto()
