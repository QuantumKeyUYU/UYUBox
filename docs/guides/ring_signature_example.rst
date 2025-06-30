# docs/guides/ring_signature_example.rst
Example – Ring Signature (3 members / 5 lines)
==============================================

This short example shows how to create and verify a ring signature with
three participants using **PQRing**.

.. code-block:: python

   from zilant_prime_core.utils.pq_ring import PQRing

   # 1) Initialise a ring-signer object and generate 3 key-pairs
   ring = PQRing()
   pubkeys = [ring.keygen() for _ in range(3)]

   # 2) Member with index 1 signs the message
   signature = ring.sign(b"hello world", pubkeys, signer_index=1)

   # 3) Anyone can verify that *someone* in the ring signed it
   assert ring.verify(b"hello world", signature, pubkeys)

   print("Valid ring signature!")

Explanation
-----------

1. ``PQRing.keygen()`` returns ``(public_key, private_key)`` and stores
   the private part inside the ``ring`` instance.
2. ``sign()`` takes the *whole* list of public keys, so the verifier can
   reconstruct the ring.
3. ``verify()`` returns ``True`` as long as the signature belongs to **any**
   of the three public keys — without revealing *which* one.
