from dataclasses import dataclass
from typing import Optional

@dataclass
class Disk:
    type: str
    size: int

@dataclass
class Volume:
    name: str
    size: int
    fs: str

@dataclass
class SystemInfo:
    disks: list[Disk]
    volumes: list[Volume]
    children: list[str]
    hostname: str
    domain: str
    ips: list[str]
    os_family: str
    os_version: str
    architecture: str
    language: list[str]
    timezone: str
    install_date: str
    last_activity: str

def parse_system_info(data: dict) -> SystemInfo:
    return SystemInfo(
        disks=[Disk(**d) for d in data["disks"]],
        volumes=[Volume(**v) for v in data["volumes"]],
        children=data["children"],
        hostname=data["hostname"],
        domain=data["domain"],
        ips=data["ips"],
        os_family=data["os_family"],
        os_version=data["os_version"],
        architecture=data["architecture"],
        language=data["language"],
        timezone=data["timezone"],
        install_date=data["install_date"],
        last_activity=data["last_activity"]
    )
