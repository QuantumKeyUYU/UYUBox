# tests/test_botocore_stub.py

import boto3
import botocore
from botocore.stub import ANY, Stubber


def test_get_session_and_client():
    sess = botocore.get_session()
    client = sess.create_client("s3")
    # put_object → всегда дает заглушку
    resp_put = client.put_object(Bucket="x", Key="y", Body=b"data")
    assert resp_put == {"ETag": "deadbeef"}
    # get_object → Body.read() == b""
    resp_get = client.get_object(Bucket="foo", Key="bar")
    assert hasattr(resp_get["Body"], "read")
    assert resp_get["Body"].read() == b""


def test_boto3_client_alias():
    client = boto3.client("s3")
    # alias на botocore.get_session().create_client
    resp = client.put_object(Bucket="a", Key="b", Body=b"z")
    assert resp == {"ETag": "deadbeef"}


def test_ANY_and_Stubber_behavior():
    a = ANY()
    assert a == "любое"
    assert a == 123

    class Dummy:
        def foo(self, **kw):
            pass

    d = Dummy()
    st = Stubber(d)
    st.add_response("foo", {"ok": True}, {"x": 1})
    st.activate()
    assert d.foo(x=1) == {"ok": True}
    st.deactivate()
