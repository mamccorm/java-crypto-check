import fnmatch
import os
import re
import argparse

# Define patterns for detecting non-FIPS compliant algorithms, weak key lengths,
# and RNGs.
non_fips_patterns = {
    'algorithms': [r'MD2', r'MD5', r'SHA1', r'DES', r'RC4'],
    'key_lengths': [
        # Tuple format: (Algorithm, Minimum Key Length)
        (r'AES', 128),
    ],
    'rngs': [r'java\.util\.Random'],  # Non-secure RNG
}

# List of cryptographic package names/patterns to search for
crypto_libs = [
    r'javax\.crypto\..*',
    r'org\.apache\.commons\.codec\..*',
    r'commons-codec',
    r'org\.jasypt\..*',
    r'com\.google\.crypto\.tink\..*',
    r'keyczar\..*',
    r'org\.bouncycastle\..*',
    r'libsodium',
    r'com\.nimbusds\..*',
    r'org\.apache\.commons\.crypto\..*',
    r'com\.neilalexander\.jnacl\..*',
    r'io\.netty\.handler\.ssl\..*',
    r'com\.wolfssl\..*',
    r'sun\.security\..*'
]

def print_findings_section(title, findings):
    if findings:
        print(f"\n{title} ({len(findings)} findings):")
        print("-" * 80)
        for item, path in sorted(findings):
            print(f"  - {item} in {path}")
        print("\n" + "=" * 80)

def check_file_content(file_path, crypto_libs, non_fips_patterns, findings):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

        for lib_pattern in crypto_libs:
            if re.search(lib_pattern, content):
                findings['libs'].add((lib_pattern, file_path))

        for algo in non_fips_patterns['algorithms']:
            if re.search(algo, content):
                findings['algorithms'].add((algo, file_path))

        for algo, min_length in non_fips_patterns['key_lengths']:
            pattern = f"{algo}[^0-9]*([0-9]{{1,3}})"
            matches = re.finditer(pattern, content)
            for match in matches:
                key_length = int(match.group(1))
                if key_length < min_length:
                    findings['key_lengths'].add((f"{algo} ({key_length} bits)", file_path))

        for rng in non_fips_patterns['rngs']:
            if re.search(rng, content):
                findings['rngs'].add((rng, file_path))

def summarize_findings(findings):
    summary_parts = ["Summary of detections:"]
    categories_full_names = {
        'libs': 'uses of potentially non-compliant cryptographic libraries',
        'algorithms': 'instances of non-FIPS compliant algorithms',
        'key_lengths': 'instances of weak key lengths',
        'rngs': 'uses of non-secure RNGs'
    }
    
    for category, items in findings.items():
        if items:
            name = categories_full_names.get(category, category)
            summary_parts.append(f"- {len(items)} {name}")
    
    summary = '\n  '.join(summary_parts)  # Indent each new line
    return summary if len(summary_parts) > 1 else "No detections found"

def search_crypto_usage(repo_path, crypto_libs, non_fips_patterns):
    findings = {
        'libs': set(),
        'algorithms': set(),
        'key_lengths': set(),
        'rngs': set(),
    }
    # Define glob patterns for files to exclude from the scan
    exclude_patterns = ['*Test.java', '*SmokeTest*']

    for root, _, files in os.walk(repo_path):
        for file in files:
            # Skip files that match any of the exclude patterns
            if any(fnmatch.fnmatch(file, pattern) for pattern in exclude_patterns):
                continue  # Skip this file

            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                check_file_content(file_path, crypto_libs, non_fips_patterns, findings)

    # Print findings, summary, and excluded patterns
    total_findings = sum(len(v) for v in findings.values())
    print(f"\nTotal Findings: {total_findings}\n")
    print("=" * 80)

    print_findings_section("Cryptographic Libraries Usage", findings['libs'])
    print_findings_section("Non-FIPS Compliant Algorithms", findings['algorithms'])
    print_findings_section("Weak Key Lengths", findings['key_lengths'])
    print_findings_section("Non-Secure RNGs", findings['rngs'])

    summary = summarize_findings(findings)
    print(f"\n{summary}\n")

    # Print excluded file patterns at the end
    excluded_patterns_str = ', '.join(exclude_patterns)
    print(f"Excluded file patterns: {excluded_patterns_str}\n")

def main():
    parser = argparse.ArgumentParser(
        description='Detect cryptographic library usage and non-FIPS compliant practices in a Java Git repository.'
    )
    parser.add_argument('repo_path', type=str, help='Path to the root directory of the Git repository')
    args = parser.parse_args()
    search_crypto_usage(args.repo_path, crypto_libs, non_fips_patterns)

if __name__ == '__main__':
    main()
