"""Base HTTP Client.

This provides convenient elements like logging requests and responses,
automatically deserializing responses into an object, etc.
"""

import dataclasses
import logging
from typing import (
    Any,
    ClassVar,
    Literal,
    Mapping,
    Protocol,
    Type,
    TypeVar,
    cast,
    overload,
    runtime_checkable,
)
from dataclasses import asdict, is_dataclass

from httpx import AsyncClient, Response


LOGGER = logging.getLogger(__name__)


class Dataclass(Protocol):
    """Empty protocol for dataclass type hinting."""

    __dataclass_fields__: ClassVar[dict[str, dataclasses.Field[Any]]]


T = TypeVar("T")


@runtime_checkable
class Serde(Protocol):
    """Object supporting serialization and deserialization methods."""

    def serialize(self) -> Mapping[str, Any]:
        """Serialize object."""
        ...

    @classmethod
    def deserialize(cls: Type[T], value: Mapping[str, Any]) -> T:
        """Deserialize value to object."""
        ...


Serializable = Dataclass | Serde | Mapping[str, Any] | None
S = TypeVar("S", bound=Serializable)


def _serialize(value: Serializable):
    """Serialize value."""
    if value is None:
        return None
    if isinstance(value, Serde):
        return value.serialize()
    if isinstance(value, Mapping):
        return value
    if is_dataclass(value):
        return asdict(value)
    raise TypeError(f"Could not serialize value {value}")


@overload
def _deserialize(value: Any) -> Mapping[str, Any]: ...


@overload
def _deserialize(value: Any, as_type: Type[T]) -> T: ...


@overload
def _deserialize(value: Any, as_type: None) -> Mapping[str, Any]: ...


def _deserialize(value: Any, as_type: Type[T] | None = None) -> T | Any:
    """Deserialize value."""
    if value is None:
        return None
    if as_type is None:
        return value
    if issubclass(as_type, Serde):
        return as_type.deserialize(value)
    if is_dataclass(as_type):
        return cast(T, as_type(**value))
    if issubclass(as_type, Mapping):
        return cast(T, value)
    raise TypeError(f"Could not deserialize value into type {as_type.__name__}")


class HTTPClientError(Exception):
    """Raised on errors in HTTP client."""


class HTTPClient:
    """Base HTTP Client."""

    def __init__(self, base_url: str, headers: dict[str, str] | None = None):
        """Init the client."""
        self.base_url = base_url
        self.headers = headers or {}

    async def _handle_response(
        self,
        resp: Response,
    ) -> Mapping[str, Any]:
        if (
            resp.status_code >= 200
            and resp.status_code < 300
            and resp.headers.get("content-type") == "application/json"
        ):
            body = resp.json()
            LOGGER.debug("%s: %s", resp.status_code, body)
            return body

        body = resp.content
        if resp.status_code >= 200 and resp.status_code < 300:
            raise HTTPClientError(
                f"Unexpected content type {resp.headers.get('content-type')}: {body}"
            )
        raise HTTPClientError(f"Request failed: {resp.url} {body}")

    async def _request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE"],
        url: str,
        *,
        data: bytes | None = None,
        json: Serializable | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: Type[T] | None = None,
    ) -> T | Mapping[str, Any]:
        """Make an HTTP request."""
        headers = dict(headers) if headers else {}
        headers.update(self.headers)

        LOGGER.info("%s %s", method, url)
        if params:
            LOGGER.debug("Query: %s", params)
        if data or json:
            LOGGER.debug("%s", data or json)

        async with AsyncClient(base_url=self.base_url, headers=headers) as session:
            if method == "GET" or method == "DELETE":
                resp = await session.request(
                    method, url, params=params, headers=headers
                )
                body = await self._handle_response(resp)
                value = _deserialize(body, response)

            elif method == "POST" or method == "PUT":
                json_ = _serialize(json)
                if not data and json_ is None:
                    json_ = {}

                resp = await session.request(
                    method, url, content=data, json=json_, params=params
                )
                body = await self._handle_response(resp)
                value = _deserialize(body, response)
            else:
                raise ValueError(f"Unsupported method {method}")

        return value

    @overload
    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]: ...

    @overload
    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: Type[T],
    ) -> T: ...

    @overload
    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: None,
    ) -> Mapping[str, Any]: ...

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: Type[T] | None = None,
    ) -> T | Mapping[str, Any]:
        """HTTP Get."""
        return await self._request(
            "GET", url, params=params, headers=headers, response=response
        )

    @overload
    async def delete(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]: ...

    @overload
    async def delete(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: None,
    ) -> Mapping[str, Any]: ...

    @overload
    async def delete(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: Type[T],
    ) -> T: ...

    async def delete(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: Type[T] | None = None,
    ) -> T | Mapping[str, Any]:
        """HTTP Delete."""
        return await self._request(
            "DELETE", url, params=params, headers=headers, response=response
        )

    @overload
    async def post(
        self,
        url: str,
        *,
        data: bytes | None = None,
        json: Serializable | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]: ...

    @overload
    async def post(
        self,
        url: str,
        *,
        data: bytes | None = None,
        json: Serializable | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: Type[T],
    ) -> T: ...

    @overload
    async def post(
        self,
        url: str,
        *,
        data: bytes | None = None,
        json: Serializable | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: None = None,
    ) -> Mapping[str, Any]: ...

    async def post(
        self,
        url: str,
        *,
        data: bytes | None = None,
        json: Serializable | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: Type[T] | None = None,
    ) -> T | Mapping[str, Any]:
        """HTTP POST."""
        return await self._request(
            "POST",
            url,
            data=data,
            json=json,
            params=params,
            headers=headers,
            response=response,
        )

    @overload
    async def put(
        self,
        url: str,
        *,
        data: bytes | None = None,
        json: Serializable | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]: ...

    @overload
    async def put(
        self,
        url: str,
        *,
        data: bytes | None = None,
        json: Serializable | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: None,
    ) -> Mapping[str, Any]: ...

    @overload
    async def put(
        self,
        url: str,
        *,
        data: bytes | None = None,
        json: Serializable | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: Type[T],
    ) -> T: ...

    async def put(
        self,
        url: str,
        *,
        data: bytes | None = None,
        json: Serializable | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        response: Type[T] | None = None,
    ) -> T | Mapping[str, Any]:
        """HTTP Put."""
        return await self._request(
            "PUT",
            url,
            data=data,
            json=json,
            params=params,
            headers=headers,
            response=response,
        )
