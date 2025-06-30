# tests/test_s3_backend.py
import pytest

import boto3
import src.backends.s3_backend as s3b
from botocore.stub import ANY, Stubber


@pytest.fixture(autouse=True)
def stub_s3(monkeypatch):
    client = boto3.client("s3", region_name="us-east-1")
    stub = Stubber(client)
    monkeypatch.setattr(boto3, "client", lambda *args, **kwargs: client)
    return stub


def test_store_and_retrieve_roundtrip(stub_s3):
    data = b"DATA"
    # stub для put_object
    stub_s3.add_response(
        "put_object",
        {},
        {"Bucket": s3b.BUCKET, "Key": ANY, "Body": data},
    )
    # stub для get_object
    stub_s3.add_response(
        "get_object",
        {"Body": type("B", (), {"read": lambda self: data})()},
        {"Bucket": s3b.BUCKET, "Key": ANY},
    )
    stub_s3.activate()

    uri = s3b.store(data)
    assert uri.startswith(f"s3://{s3b.BUCKET}/")
    got = s3b.retrieve(uri)
    assert got == data


def test_retrieve_invalid_uri():
    with pytest.raises(ValueError):
        s3b.retrieve("file://nope")
