# docs/guides/tor_proxy_qvpn.rst
Tor Proxy via QVPN
===================

This guide shows how to route your traffic through Tor using QVPN.

Prerequisites
-------------
- Installed QVPN (see `API Reference <../api/qvpn.html>`_).
- Tor running locally (default SOCKS port 9050).

Configuration
-------------
Create a `config.toml` for QVPN, for example:

.. code-block:: toml

   [qvpn]
   mode = "tor"
   socks_port = 9050
   listen_port = 1080

Launch QVPN in Tor mode
-----------------------

Run:

.. code-block:: bash

   qvpn --config path/to/config.toml up

Check that QVPN proxy is listening:

.. code-block:: bash

   netstat -tunlp | grep 1080

Test via curl
-------------

Use curl with the SOCKS5 proxy to verify Tor exit:

.. code-block:: bash

   curl --socks5-hostname localhost:1080 https://check.torproject.org

You should see a page confirming you’re using Tor.

Cleanup
-------

To bring the interface down:

.. code-block:: bash

   qvpn --config path/to/config.toml down
