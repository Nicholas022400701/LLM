# jobs/

One directory per job: `jobs/<jobId>/` containing either `input.enc.b64` or `input.enc.b64.partNNN` + `parts.json`, plus `meta.json` (byte counts and package-level SHA-256 only). Nothing else may be present in the directory.

`jobId` must have the form `j-YYYYMMDD-xxxxxx` (a date, then 6 hex characters); the workflow's Audit step fails otherwise. Results are written by the workflow to the `results` branch under `results/<jobId>/`.
