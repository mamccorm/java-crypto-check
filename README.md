# java-fips-check

> THIS IS NOT CONCLUSIVE, AND IS LARGELY AN EXPERIMENT AT THIS POINT. DO NOT
> TREAT THIS AS AN AUTHORATIVE SOURCE OF TRUTH.

A python script which scans a Java applications source code, to look for usage
of bundled crypto librarys, as well as crypto algorithms not permitted under
FIPS 140-2.

The purpose of this script is to aid decision making when determining if a Java
application can be made FIPS compliant.

This is not intended to be a Yes/No check, but more a developer tool to provide
additional information in the exploratory process.

## Running:

```bash
python3 scan.py /path/to/your/source/code
```

If matches are found, each match (filepath) will be printed to the console log,
as well as a summary:

```bash
# Individual matches printed here...
# ...

Detailed Summary of Detections:
  - 48 instance(s) of: javax.crypto
  - 49 instance(s) of: apache commons codec
  - 6 instance(s) of: bouncy castle
  - 88 instance(s) of: md5
  - 12 instance(s) of: sha1
  - 365 instance(s) of: des
  - 3 instance(s) of: rc4

Excluded file patterns: *Test.java, *SmokeTest*
```
