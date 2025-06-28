# PC App

A minimal command line tool to encrypt and decrypt files with AES-GCM.

## Usage

```bash
pc-app pack input.txt encrypted.bin
pc-app unpack encrypted.bin output.txt
```

The tool tracks the number of decryptions and can enforce one-time or limited-use containers.
