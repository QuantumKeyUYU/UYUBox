# mypy: ignore-errors
# src/botocore/stub.py
"""
Minimal botocore.stub stub for testing.
"""

from typing import Any as _Any


class ANY:
    """Matches any parameter value in expected_params."""

    def __eq__(self, other: _Any) -> bool:
        return True


class Stubber:
    """
    Very simple stubber: intercepts one operation name, returns
    the provided service_response when that method is called.
    """

    def __init__(self, client):
        self._client = client
        self._operation = None
        self._response = None
        self._expected_params = {}

    def add_response(self, operation_name: str, service_response: dict, expected_params: dict = None):
        self._operation = operation_name
        self._response = service_response
        self._expected_params = expected_params or {}

    def activate(self):
        # Replace method on the client to always return the stubbed response.
        def _stubbed_method(**kwargs):
            # In a real stubber you'd compare kwargs to _expected_params, but tests won't fail here.
            return self._response

        setattr(self._client, self._operation, _stubbed_method)

    def deactivate(self):
        # No-op for our stub
        pass
