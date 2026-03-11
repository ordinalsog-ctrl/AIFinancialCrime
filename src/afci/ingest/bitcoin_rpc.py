from __future__ import annotations

import requests
from typing import Any


class BitcoinRpcClient:
    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = url
        self.auth = (user, password)

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        payload = {
            "jsonrpc": "1.0",
            "id": "afci",
            "method": method,
            "params": params or [],
        }
        resp = requests.post(self.url, json=payload, auth=self.auth, timeout=30)
        resp.raise_for_status()
        body = resp.json()
        if body.get("error"):
            raise RuntimeError(f"RPC error: {body['error']}")
        return body["result"]
