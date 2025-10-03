## Revoked CVEs

```shell
python3 run_cve2stix.py mod \
	--earliest 2024-04-01T00:00:00 \
	--latest 2024-04-10T00:00:00 \
	--file_time_range 1d
```

## A good mix of CVEs (inc CVE with multiple CVSS 3.1 scores -- CVE-2024-9358)

```shell
python3 run_cve2stix.py pub \
	--earliest 2024-10-01T00:00:00 \
	--latest 2024-10-01T23:59:59 \
	--file_time_range 1d
```