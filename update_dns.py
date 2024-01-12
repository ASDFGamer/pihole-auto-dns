#!/usr/bin/env python3

# pylint: disable=missing-function-docstring,missing-module-docstring,missing-class-docstring

from enum import Enum
import os
from urllib.error import HTTPError
import urllib.request
import urllib.parse
import json
from typing import Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class EnvVars:
    pihole_base_url: str = os.environ["pihole_base_url"]
    pihole_password: str = os.environ["pihole_password"]
    config_file: str = os.environ.get("config_file", default="/pihole_config.json")
    docker_endpoint: Optional[str] = os.environ.get("docker_endpoint")
    default_cname_target: Optional[str] = os.environ.get(
        "default_cname_target", default=None
    )
    cache_file = "/tmp/pihole_auth.json"


@dataclass(frozen=True)
class ApiError:
    key: str
    message: str
    hint: Optional[str]
    error_code: int
    url: str


@dataclass(frozen=True)
class PiholeAuth:
    valid: bool
    totp: bool
    sid: str
    csrf: str
    validity: int
    creation_time: datetime = datetime.now()

    @classmethod
    def get_valid(cls) -> "PiholeAuth":
        if os.path.isfile(EnvVars.cache_file):
            with open(EnvVars.cache_file, mode="r", encoding="UTF-8") as cache_file:
                old_auth_json = json.load(cache_file)
                old_auth = PiholeAuth.from_json(old_auth_json)
                delta = datetime.now() - old_auth.creation_time
                if delta.seconds < old_auth.validity:
                    return old_auth
        new_auth = cls.get_new()
        new_auth_json = new_auth.to_json()
        with open(EnvVars.cache_file, mode="w", encoding="UTF-8") as cache_file:
            cache_file.write(new_auth_json)
        return new_auth

    @classmethod
    def get_new(cls) -> "PiholeAuth":
        api_url = f"{EnvVars.pihole_base_url}/api/auth"
        json_data = {"password": EnvVars.pihole_password}
        result: ApiResponse = rest_request(
            url=api_url, data=json_data, method=HttpMethod.POST
        )
        if result.code != 200:
            raise ValueError("Invalid Password")
        if result.json is None:
            raise ValueError("No Data returned")
        return PiholeAuth(**result.json["session"])

    @classmethod
    def from_json(cls, json_obj: Any) -> "PiholeAuth":
        json_obj["creation_time"] = datetime.fromisoformat(json_obj["creation_time"])
        return PiholeAuth(**json_obj)

    def to_json(self) -> str:
        def converter(o: Any):
            if isinstance(o, datetime):
                return o.isoformat()

        return json.dumps(asdict(self), default=converter)


HttpMethod = Enum("HTTP_Method", ["GET", "POST", "PUT", "DELETE"])


@dataclass
class ApiResponse:
    code: int
    json: Optional[Any]


def rest_request(
    url: str,
    method: HttpMethod,
    data: Optional[dict[str, str]] = None,
    headers: Optional[dict[str, str]] = None,
    auth: Optional[PiholeAuth] = None,
) -> ApiResponse:
    request = urllib.request.Request(url, method=method.name.upper())
    if headers:
        for key, value in headers.items():
            request.add_header(key=key, val=value)
    if auth:
        request.add_header(key="X-CSRF-TOKEN", val=auth.csrf)
        request.add_header(key="Cookie", val=f"sid={auth.sid}")
    if data:
        request.add_header("Content-Type", "application/json")
        json_data = json.dumps(data).encode()
    else:
        json_data = None
    try:
        with urllib.request.urlopen(request, data=json_data) as response:
            body: str = response.read().decode("utf-8")
            if body:
                json_response = json.loads(body)
            else:
                json_response = None
            return ApiResponse(code=response.status, json=json_response)
    except HTTPError as err:
        error_message = json.loads(err.fp.read())["error"]
        api_error = ApiError(**error_message, error_code=err.code, url=err.url)
        raise ValueError(api_error) from err


@dataclass(frozen=True)
class DockerContainer:
    id: str
    labels: dict[str, str]

    @classmethod
    def get_running_containers(cls, docker_endpoint: str) -> list["DockerContainer"]:
        result: list[DockerContainer] = []
        api_url = docker_endpoint + "/containers/json"
        response = rest_request(url=api_url, method=HttpMethod.GET)
        if response.code != 200 or response.json is None:
            raise ValueError("Can't get containers from docker endpoint")
        for container in response.json:
            result.append(
                DockerContainer(id=container["Id"], labels=container["Labels"])
            )
        return result


@dataclass(frozen=True)
class DnsRecord:
    domain: str
    ip: str

    def remove(self, auth: PiholeAuth):
        api_url = (
            f"{EnvVars.pihole_base_url}/api/config/dns/hosts/{self.ip}%20{self.domain}"
        )
        rest_request(url=api_url, auth=auth, method=HttpMethod.DELETE)
        print(f"Removed DNS Record from pihole: domain: {self.domain}, ip: {self.ip}")

    def add(self, auth: PiholeAuth):
        api_url = (
            f"{EnvVars.pihole_base_url}/api/config/dns/hosts/{self.ip}%20{self.domain}"
        )
        rest_request(url=api_url, auth=auth, method=HttpMethod.PUT)
        print(f"Added DNS Record to pihole: domain: {self.domain}, ip: {self.ip}")


@dataclass(frozen=True)
class CNameRecord:
    domain: str
    target: str

    def remove(self, auth: PiholeAuth):
        api_url = f"{EnvVars.pihole_base_url}/api/config/dns/cnameRecords/{self.domain}%2C{self.target}"
        rest_request(url=api_url, auth=auth, method=HttpMethod.DELETE)
        print(
            f"Removed CName from pihole: domain: {self.domain}, target: {self.target}"
        )

    def add(self, auth: PiholeAuth):
        api_url = f"{EnvVars.pihole_base_url}/api/config/dns/cnameRecords/{self.domain}%2C{self.target}"
        rest_request(url=api_url, auth=auth, method=HttpMethod.PUT)
        print(f"Added CName to pihole: domain: {self.domain}, target: {self.target}")

    @classmethod
    def load_from_docker_labels(cls) -> list["CNameRecord"]:
        if EnvVars.docker_endpoint is None:
            return []

        result: list[CNameRecord] = []
        running_containers = DockerContainer.get_running_containers(
            EnvVars.docker_endpoint
        )
        cname_label = "pihole_config.local_dns.cname"
        domain_label = f"{cname_label}.domain"
        target_label = f"{cname_label}.target"
        for container in running_containers:
            if domain_label in container.labels:
                if target_label in container.labels:
                    target = container.labels[target_label]
                else:
                    if EnvVars.default_cname_target is None:
                        raise ValueError(
                            "Please provide a cname target, either as a label or via the default_cname_target env var"
                        )
                    target = EnvVars.default_cname_target
                result.append(
                    CNameRecord(
                        domain=container.labels[domain_label],
                        target=target,
                    )
                )
        return result


@dataclass(frozen=True)
class LocalDnsConfig:
    dns: list[DnsRecord]
    cname: list[CNameRecord]

    @classmethod
    def load_from_json(cls, json_config: Any) -> "LocalDnsConfig":
        dnsRecords: list[DnsRecord] = []
        cnameRecords: list[CNameRecord] = []

        if "DNS" in json_config:
            for record in json_config["DNS"]:
                dnsRecords.append(DnsRecord(ip=record["ip"], domain=record["domain"]))
        if "CNAME" in json_config:
            for record in json_config["CNAME"]:
                cnameRecords.append(
                    CNameRecord(target=record["target"], domain=record["domain"])
                )
        cnameRecords = cnameRecords + CNameRecord.load_from_docker_labels()
        return LocalDnsConfig(dns=dnsRecords, cname=cnameRecords)


@dataclass(frozen=True)
class PiholeConfig:
    local_dns: LocalDnsConfig

    @classmethod
    def load_from_file(cls, filename: str) -> "PiholeConfig":
        with open(filename, mode="r", encoding="UTF-8") as config_file:
            parsed_config = json.load(config_file)
            return cls.load_from_json(parsed_config)

    @classmethod
    def load_from_json(cls, json_config: Any) -> "PiholeConfig":
        local_dns_config = LocalDnsConfig(dns=[], cname=[])
        for key in json_config.keys():
            if key == "local_dns":
                local_dns_config = LocalDnsConfig.load_from_json(json_config[key])
        return PiholeConfig(local_dns=local_dns_config)


def get_current_cname_records(auth: PiholeAuth) -> list[CNameRecord]:
    api_url = f"{EnvVars.pihole_base_url}/api/config/dns/cnameRecords/"
    api_result: ApiResponse = rest_request(
        url=api_url, auth=auth, method=HttpMethod.GET
    )
    if api_result.code != 200 or api_result.json is None:
        raise ValueError("Can't get current CName Records")
    record_list: list[str] = api_result.json["config"]["dns"]["cnameRecords"]
    result: list[CNameRecord] = []
    for record in record_list:
        (domain, target) = record.split(",", maxsplit=1)
        result.append(CNameRecord(domain=domain, target=target))
    return result


def get_current_dns_records(auth: PiholeAuth) -> list[DnsRecord]:
    api_url = f"{EnvVars.pihole_base_url}/api/config/dns/hosts/"
    api_result: ApiResponse = rest_request(
        url=api_url, auth=auth, method=HttpMethod.GET
    )
    if api_result.code != 200 or api_result.json is None:
        raise ValueError("Can't get current DNS Records")
    record_list: list[str] = api_result.json["config"]["dns"]["hosts"]
    result: list[DnsRecord] = []
    for record in record_list:
        (ip, domain) = record.split(" ", maxsplit=1)
        result.append(DnsRecord(domain=domain, ip=ip))
    return result


def apply_local_dns_records(auth: PiholeAuth, config: PiholeConfig):
    current_dns = get_current_dns_records(auth)
    expected_dns = config.local_dns.dns

    to_add = [x for x in current_dns + expected_dns if x not in current_dns]

    to_remove = [x for x in current_dns + expected_dns if x not in expected_dns]

    for dns in to_remove:
        dns.remove(auth)

    for dns in to_add:
        dns.add(auth)


def apply_local_cname_records(auth: PiholeAuth, config: PiholeConfig):
    current_cname = get_current_cname_records(auth)
    expected_cname = config.local_dns.cname

    to_add = [x for x in current_cname + expected_cname if x not in current_cname]

    to_remove = [x for x in current_cname + expected_cname if x not in expected_cname]

    for cname in to_remove:
        cname.remove(auth)

    for cname in to_add:
        cname.add(auth)


def apply_local_dns(auth: PiholeAuth, config: PiholeConfig):
    apply_local_dns_records(auth, config)
    apply_local_cname_records(auth, config)


def apply_config(auth: PiholeAuth, config: PiholeConfig):
    apply_local_dns(auth, config)


def main() -> None:
    pihole_auth: PiholeAuth = PiholeAuth.get_valid()
    pihole_config: PiholeConfig = PiholeConfig.load_from_file(EnvVars.config_file)
    apply_config(config=pihole_config, auth=pihole_auth)


if __name__ == "__main__":
    main()
