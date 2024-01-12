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
            url=api_url, body=json_data, method=HttpMethod.POST
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
    body: Optional[dict[str, Any]] = None,
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
    if body:
        request.add_header("Content-Type", "application/json")
        json_data = json.dumps(body).encode()
    else:
        json_data = None
    try:
        with urllib.request.urlopen(request, data=json_data) as response:
            response_body: str = response.read().decode("utf-8")
            if response_body:
                json_response = json.loads(response_body)
            else:
                json_response = None
            return ApiResponse(code=response.status, json=json_response)
    except HTTPError as err:
        error_message = json.loads(err.fp.read())["error"]
        api_error = ApiError(**error_message, error_code=err.code, url=err.url)
        raise ValueError(api_error) from err


def pihole_api_get(auth: PiholeAuth, api_path: str) -> Any:
    if api_path.startswith("/"):
        api_path = api_path.lstrip("/")
    api_url = f"{EnvVars.pihole_base_url}/api/{api_path}"
    api_result: ApiResponse = rest_request(
        url=api_url, auth=auth, method=HttpMethod.GET
    )
    if api_result.code != 200 or api_result.json is None:
        raise ValueError("Can't get current DNS Records")
    return api_result.json


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

    @classmethod
    def current_remote_state(cls, auth: PiholeAuth):
        json_result = pihole_api_get(auth, "config/dns/hosts/")
        record_list: list[str] = json_result["config"]["dns"]["hosts"]
        result: list[DnsRecord] = []
        for record in record_list:
            (ip, domain) = record.split(" ", maxsplit=1)
            result.append(DnsRecord(domain=domain, ip=ip))
        return result


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

    @classmethod
    def current_remote_state(cls, auth: PiholeAuth) -> list["CNameRecord"]:
        json_result = pihole_api_get(auth, "config/dns/cnameRecords/")
        record_list: list[str] = json_result["config"]["dns"]["cnameRecords"]
        result: list[CNameRecord] = []
        for record in record_list:
            (domain, target) = record.split(",", maxsplit=1)
            result.append(CNameRecord(domain=domain, target=target))
        return result


@dataclass(frozen=True)
class LocalDnsConfig:
    dns: list[DnsRecord]
    cname: list[CNameRecord]

    @classmethod
    def from_json(cls, json_config: Any) -> "LocalDnsConfig":
        dns_records: list[DnsRecord] = []
        cname_records: list[CNameRecord] = []

        if "DNS" in json_config:
            for record in json_config["DNS"]:
                dns_records.append(DnsRecord(ip=record["ip"], domain=record["domain"]))
        if "CNAME" in json_config:
            for record in json_config["CNAME"]:
                cname_records.append(
                    CNameRecord(target=record["target"], domain=record["domain"])
                )
        cname_records = cname_records + CNameRecord.load_from_docker_labels()
        return LocalDnsConfig(dns=dns_records, cname=cname_records)

    def apply(self, auth: PiholeAuth):
        self._apply_dns(auth)
        self._apply_cname(auth)

    def _apply_dns(self, auth: PiholeAuth):
        current_dns = DnsRecord.current_remote_state(auth)

        to_add = [x for x in current_dns + self.dns if x not in current_dns]

        to_remove = [x for x in current_dns + self.dns if x not in self.dns]

        for dns in to_remove:
            dns.remove(auth)

        for dns in to_add:
            dns.add(auth)

    def _apply_cname(self, auth: PiholeAuth):
        current_cname = CNameRecord.current_remote_state(auth)
        to_add = [x for x in current_cname + self.cname if x not in current_cname]

        to_remove = [x for x in current_cname + self.cname if x not in self.cname]

        for cname in to_remove:
            cname.remove(auth)

        for cname in to_add:
            cname.add(auth)


@dataclass(frozen=True)
class DomainRecord:
    domain: str
    # allow or deny
    allow: bool
    # exact or regex
    exact: bool = True
    comment: Optional[str] = None

    @classmethod
    def from_json(cls, json_config: Any) -> "DomainRecord":
        exact = True
        if "kind" in json_config:
            kind: str = json_config["kind"].lower()
            if kind == "regex":
                exact = False
            elif kind != "exact":
                print(
                    f"Warning: Domain kind can only be 'regex' or 'exact' and not '{kind}'"
                )
        allow = True
        domain_type: str = json_config["kind"].lower()
        if domain_type == "deny":
            exact = False
        elif domain_type != "allow":
            print(
                f"Warning: Domain type can only be 'allow' or 'deny' and not '{domain_type}'"
            )
        return DomainRecord(
            domain=json_config["domain"],
            exact=exact,
            comment=json_config.get("comment", None),
            allow=allow,
        )

    @classmethod
    def current_remote_state(cls, auth: PiholeAuth) -> list["DomainRecord"]:
        json_result = pihole_api_get(auth, "domains")
        domain_list: list[Any] = json_result["domains"]
        result: list[DomainRecord] = []
        for domain_json in domain_list:
            exact: bool = domain_json["kind"] == "exact"
            allow: bool = domain_json["type"] == "allow"
            result.append(
                DomainRecord(
                    domain=domain_json["domain"],
                    exact=exact,
                    comment=domain_json["comment"],
                    allow=allow,
                )
            )

        return result

    def remove(self, auth: PiholeAuth):
        domain_type = "allow" if self.allow else "deny"
        kind = "exact" if self.exact else "regex"
        api_url = (
            f"{EnvVars.pihole_base_url}/api/domains/{domain_type}/{kind}/{self.domain}"
        )
        rest_request(url=api_url, auth=auth, method=HttpMethod.DELETE)
        if self.allow:
            print(f"Removed allowed Domain from pihole: {self.domain} ")
        else:
            print(f"Removed denied Domain from pihole: {self.domain} ")

    def add(self, auth: PiholeAuth):
        domain_type = "allow" if self.allow else "deny"
        kind = "exact" if self.exact else "regex"
        api_url = f"{EnvVars.pihole_base_url}/api/domains/{domain_type}/{kind}"
        body = {
            "domain": self.domain,
            "comment": self.comment,
            "enabled": True,
            "groups": 1,
        }
        rest_request(url=api_url, auth=auth, method=HttpMethod.POST, body=body)
        if self.allow:
            print(f"Added allowed Domain to pihole: {self.domain} ")
        else:
            print(f"Added denied Domain to pihole: {self.domain} ")


@dataclass(frozen=True)
class DomainConfig:
    domains: list[DomainRecord]

    @classmethod
    def from_json(cls, json_config: Any) -> "DomainConfig":
        domains: list[DomainRecord] = []
        for domain_config in json_config:
            domains.append(DomainRecord.from_json(domain_config))
        return DomainConfig(domains=domains)

    def apply(self, auth: PiholeAuth):
        current_remote_state = DomainRecord.current_remote_state(auth)

        to_add = [
            x
            for x in current_remote_state + self.domains
            if x not in current_remote_state
        ]

        to_remove = [
            x for x in current_remote_state + self.domains if x not in self.domains
        ]

        for dns in to_remove:
            dns.remove(auth)

        for dns in to_add:
            dns.add(auth)


@dataclass(frozen=True)
class PiholeConfig:
    local_dns: LocalDnsConfig
    domains: DomainConfig

    @classmethod
    def from_file(cls, filename: str) -> "PiholeConfig":
        with open(filename, mode="r", encoding="UTF-8") as config_file:
            parsed_config = json.load(config_file)
            return cls.from_json(parsed_config)

    @classmethod
    def from_json(cls, json_config: Any) -> "PiholeConfig":
        local_dns_config = LocalDnsConfig(dns=[], cname=[])
        domains_config = DomainConfig([])
        for key in json_config.keys():
            if key == "local_dns":
                local_dns_config = LocalDnsConfig.from_json(json_config[key])
            if key == "domains":
                domains_config = DomainConfig.from_json(json_config[key])
        return PiholeConfig(local_dns=local_dns_config, domains=domains_config)

    def apply(self, auth: PiholeAuth):
        self.local_dns.apply(auth)


def main() -> None:
    pihole_auth: PiholeAuth = PiholeAuth.get_valid()
    pihole_config: PiholeConfig = PiholeConfig.from_file(EnvVars.config_file)
    pihole_config.apply(auth=pihole_auth)


if __name__ == "__main__":
    main()
