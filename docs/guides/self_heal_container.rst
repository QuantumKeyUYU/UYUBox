Self-Healing Containers
======================

This experimental feature monitors ``.zil`` files and rotates encryption
keys when a modification is detected. A tiny proof of integrity is
produced for every event and an optional self-destruct can wipe the
container entirely.

Usage Example
-------------

.. code-block:: bash

   zilctl heal-scan secret.zil --auto
   zilctl heal-verify secret.zil

The ``heal-scan`` command attempts to repair damaged containers. When
healing succeeds a new key is generated and stored in the container's
``recovery_key_hex`` field along with a ``.proof`` file. To verify this
proof later run ``heal-verify`` which will read ``file.zil.proof`` and
check it against the last entry in ``heal_history``.

Recovery Key Usage
------------------

The ``recovery_key_hex`` value can be used to decrypt the container if the
original key was lost. Provide it instead of the old password when calling
``unpack`` or use ``--recovery-key`` in CLI tools.
