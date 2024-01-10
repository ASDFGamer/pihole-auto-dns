#!/bin/env python3

# pylint: disable=missing-function-docstring,missing-module-docstring,missing-class-docstring

from enum import Enum
import os
from urllib.error import HTTPError
import urllib.request
import urllib.parse
import json
from typing import Any, Optional
from datetime import datetime
from dataclasses import dataclass


@dataclass
class EnvVars:
    pihole_base_url = os.environ["pihole_base_url"]
    pihole_password = os.environ["pihole_password"]
    pihole_config_path = os.environ["pihole_config_path"]


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
    def get_new(cls) -> "PiholeAuth":
        api_url = "/api/auth"
        json_data = {"password": EnvVars.pihole_password}
        result: ApiResponse = rest_request(
            url=api_url, data=json_data, method=HttpMethod.POST
        )
        if result.code != 200:
            raise ValueError("Invalid Password")
        if result.json is None:
            raise ValueError("No Data returned")
        return PiholeAuth(**result.json["session"])


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
    request = urllib.request.Request(
        EnvVars.pihole_base_url + url, method=method.name.upper()
    )
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
            print(body)
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
class DnsRecord:
    domain: str
    ip: str

    def remove(self, auth: PiholeAuth):
        api_url = f"/api/config/dns/hosts/{self.ip}%20{self.domain}"
        rest_request(url=api_url, auth=auth, method=HttpMethod.DELETE)

    def add(self, auth: PiholeAuth):
        api_url = f"/api/config/dns/hosts/{self.ip}%20{self.domain}"
        rest_request(url=api_url, auth=auth, method=HttpMethod.PUT)


@dataclass(frozen=True)
class CNameRecord:
    domain: str
    target: str

    def remove(self, auth: PiholeAuth):
        api_url = f"/api/config/dns/cnameRecords/{self.domain}%2C{self.target}"
        json_data = {"password": EnvVars.pihole_password}
        rest_request(url=api_url, data=json_data, auth=auth, method=HttpMethod.DELETE)

    def add(self, auth: PiholeAuth):
        api_url = f"/api/config/dns/cnameRecords/{self.domain}%2C{self.target}"
        json_data = {"password": EnvVars.pihole_password}
        rest_request(url=api_url, data=json_data, auth=auth, method=HttpMethod.PUT)


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
    api_url = "/api/config/dns/cnameRecords/"
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
    api_url = "/api/config/dns/hosts/"
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
    pihole_auth: PiholeAuth = PiholeAuth.get_new()
    pihole_config: PiholeConfig = PiholeConfig.load_from_file(
        EnvVars.pihole_config_path
    )
    apply_config(config=pihole_config, auth=pihole_auth)


if __name__ == "__main__":
    main()
