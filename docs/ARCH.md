# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core Contributors

# Architecture Overview

```mermaid
flowchart TD
    CLI["CLI\n(zilctl)"] --> Core
    Core["Core Library"] --> Logger["Secure Logger"]
    Core --> Vault["Vault/Pseudo‑HSM"]
    Core --> SBOM["SBOM tools"]
```

- **CLI** – user facing commands.
- **Core Library** – cryptography and container logic.
- **Secure Logger** – encrypts audit logs with AES‑GCM.
- **Vault/Pseudo‑HSM** – secrets storage.
- **SBOM tools** – reproducible builds and vulnerability scanning.

## CLI-интерфейс

- `zilctl hsm init`  \
  Инициализирует HSM: создаёт файлы lock.json и counter.txt.
- `zilctl hsm seal --master-key <путь> --threshold N --shares M --output-dir <директория>`  \
  Разбивает мастер-ключ на M шардов shard_1.hex … shard_M.hex.
- `zilctl hsm unseal --input-dir <директория> --output-file <файл>`  \
  Восстанавливает мастер-ключ из шардов.
- `zilctl hsm status`  \
  Выводит JSON с полями `created` (timestamp) и `counter`.

## ISO-27001 SoA

Проект сопровождает файл `iso_soa.json` с таблицей соответствия контролям
международного стандарта ISO-27001.

## SBOM

При каждом пуше в ветку `main` GitHub Actions выполняет workflow `sbom.yml`.
Он устанавливает утилиту Syft и генерирует список зависимостей в формате
CycloneDX. Полученный файл `sbom/cyclonedx.json` сохраняется как артефакт CI.
