import fnmatch
import os
import re
import argparse

# Define patterns for detecting non-FIPS compliant algorithms, weak key lengths, and RNGs.
non_fips_patterns = {
    'algorithms': {
        'MD2': r'MD2',
        'MD5': r'MD5',
        'SHA1': r'SHA1',
        'DES': r'DES',
        'RC4': r'RC4',
    },
    'key_lengths': [(r'AES', 128)],
    'rngs': [r'java\.util\.Random'],
}

# List of cryptographic package names/patterns to search for
crypto_libs = {
    'javax.crypto': r'javax\.crypto\..*',
    'Apache Commons Codec': r'org\.apache\.commons\.codec\..*',
    'Jasypt': r'org\.jasypt\..*',
    'Google Tink': r'com\.google\.crypto\.tink\..*',
    'Bouncy Castle': r'org\.bouncycastle\..*',
    # Add other libraries as needed
}

def check_file_content(file_path, findings):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

        # Check for cryptographic library usage
        for lib_name, lib_pattern in crypto_libs.items():
            if re.search(lib_pattern, content):
                findings['Libraries'][lib_name].add(file_path)

        # Check for non-FIPS compliant algorithms
        for algo_name, algo_pattern in non_fips_patterns['algorithms'].items():
            if re.search(algo_pattern, content):
                findings['Algorithms'][algo_name].add(file_path)

        # Add checks for key lengths and RNGs as needed

def print_findings_section(findings):
    for category, items in findings.items():
        # Adjust the heading for algorithm findings to indicate potential non-permitted usage
        display_category = "Potential Non-Permitted Algorithms" if category == "Algorithms" else f"{category} Findings"
        print(f"\n{display_category}:")
        print("=" * 80)
        for name, paths in items.items():
            if paths:
                print(f"\n{name} ({len(paths)} findings):")
                print("-" * 80)
                for path in sorted(paths):
                    print(f"  - {path}")

def summarize_findings(findings):
    summary_parts = ["\nDetailed Summary of Detections:"]
    for category, items in findings.items():
        for name, paths in items.items():
            if paths:
                # Customize the description for algorithms to indicate potential non-compliance
                display_name = f"Potential Non-Permitted Algorithm: {name}" if category == "Algorithms" else f"{category[:-1]}: {name}"
                summary_parts.append(f"- {len(paths)} instances of {display_name.lower()}")

    if len(summary_parts) == 1:  # Only the header exists, no findings
        return "No detections found."

    return '\n  '.join(summary_parts)

def search_crypto_usage(repo_path):
    findings = {
        'Libraries': {lib_name: set() for lib_name in crypto_libs.keys()},
        'Algorithms': {algo_name: set() for algo_name in non_fips_patterns['algorithms'].keys()},
    }
    exclude_patterns = ['*Test.java', '*SmokeTest*']

    for root, _, files in os.walk(repo_path):
        for file in files:
            if any(fnmatch.fnmatch(file, pattern) for pattern in exclude_patterns):
                continue  # Skip excluded files

            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                check_file_content(file_path, findings)

    print_findings_section(findings)

    # Print the section breaker before the summary
    print("\n" + "=" * 80)

    # Print the verbose summary of detections
    summary = summarize_findings(findings)
    print(summary)

    # Print excluded file patterns at the end
    excluded_patterns_str = ', '.join(exclude_patterns)
    print(f"\nExcluded file patterns: {excluded_patterns_str}\n")


def main():
    parser = argparse.ArgumentParser(description='Detect cryptographic library usage and non-FIPS compliant practices in a Java Git repository.')
    parser.add_argument('repo_path', type=str, help='Path to the root directory of the Git repository')
    args = parser.parse_args()
    search_crypto_usage(args.repo_path)

if __name__ == '__main__':
    main()
