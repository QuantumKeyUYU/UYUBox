# Quantum Anonymity Layer

`QAL` creates a small group of post‑quantum signers. Messages are signed with
one of the group's secret keys and verified against every public key, providing
basic ring‑style anonymity.

```python
from pathlib import Path
from zilant_prime_core.utils import QAL

group = QAL(3, Path('/tmp/qal'))
sig = group.sign(b'msg', 0)
pubs = [p.read_bytes() for _, p in group.keys]
assert group.verify(b'msg', sig, pubs)
```

## Stealth Addresses

`QSSA` demonstrates stealth addresses with X25519. Use `generate_keypair()` to
create a temporary key and `derive_shared_address()` with the other party's
public key.

```python
from zilant_prime_core.utils import QSSA

q = QSSA()
pub, priv = q.generate_keypair()
```
