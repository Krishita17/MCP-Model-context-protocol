# Zip Slip

The server extracts zip archives using `os.path.join()` without validating entry names. A zip containing `../../../etc/cron.d/backdoor` escapes the destination directory and writes to arbitrary paths.
