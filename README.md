# LLM

Encrypted batch job runner on GitHub Actions: inputs and outputs live in this repository only as AES-256-GCM ciphertext (see `tools/cryptBox.py`); the key is a repository secret `LLM_DATA_KEY` and never appears in logs. Jobs go to `jobs/<jobId>/`, results come back on the `results` branch under `results/<jobId>/`.
