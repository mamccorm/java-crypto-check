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
  - 31 instance(s) of library: javax.crypto
  - 2 instance(s) of library: apache commons codec
  - 18 instance(s) of library: bouncyCastle
  - 3 instance(s) of potential non-permitted algorithm: md5
  - 30 instance(s) of potential non-permitted algorithm: sha1
  - 119 instance(s) of potential non-permitted algorithm: des

Excluded file patterns: *Test.java, *SmokeTest*
```
