# ZilantFS

`ZilantFS` mounts a `.zil` container as a normal directory. Files inside the mount
point are transparently decrypted or encrypted using the Zilant Prime Core crypto
engine.

## Usage

```bash
zilant mount secret.zil mnt -p -
# work with files
zilant umount mnt
```

Install optional dependencies with:

```bash
pip install "zilant-prime-core[zilfs]"
```

The implementation relies on **fusepy** on Unix and **winfspy** on Windows.

## Requirements

- **Linux**: install `fuse3` and `libfuse3-dev` packages.
- **macOS**: install `macfuse` via Homebrew.
- **Windows**: install [WinFSP](https://winfsp.dev/) and the Python package `winfspy`.

## Examples

Synchronise a directory using `rsync`:

```bash
zilant mount secret.zil mnt -p mypwd
rsync -av mnt/ backup/
zilant umount mnt
```

Use TimeMachine (macOS) to back up the mounted folder:

```bash
zilant mount data.zil /Volumes/Secure -p mypwd
tmutil startbackup --destination /Volumes/Secure
```

## Security notes

- Containers are integrity checked on mount. On failure the filesystem is mounted read‑only and a warning is logged.
- Decoy mode (`--decoy-profile minimal`) exposes fake files without touching the real container.

## Snapshots

Create a new snapshot:

```bash
zilant snapshot data.zil --label v1 --password mypwd
```

Show diff between two snapshots:

```bash
zilant diff data_v1.zil data_v2.zil --password mypwd
```

## Remote mount and tray

Mount container via SSH:

```bash
zilant mount data.zil mnt --remote user@host:/remote/data.zil -p mypwd
```

The `zilant tray` command launches a small system tray helper showing active mounts.

The adaptive decoy profile generates random fake files:

```bash
zilant mount data.zil mnt --decoy-profile adaptive -p mypwd
```

Large directories can be packed in streaming mode (set `ZILANT_STREAM=1`).

## Android Usage

The proof-of-concept Android app demonstrates unpacking `.zil` containers using JNI.
Install the debug build on an emulator:

```bash
adb install -r mobile/android/app/build/outputs/apk/debug/app-debug.apk
```

Open the app to view files extracted from `sample.zil`.

![android](../assets/android_poc.png)
