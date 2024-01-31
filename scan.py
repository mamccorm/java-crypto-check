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

def check_file_content(file_path, crypto_libs, non_fips_patterns):
    """
    Check the content of a given file for usage of specified cryptographic
    libraries and non-FIPS compliant patterns including algorithms,
    key lengths, and RNGs.
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

        # Check for cryptographic library usage
        for lib_pattern in crypto_libs:
            if re.search(lib_pattern, content):
                print(f"Found usage of {lib_pattern} in {file_path}")

        # Check for non-FIPS compliant algorithms
        for algo in non_fips_patterns['algorithms']:
            if re.search(algo, content):
                print(f"Found non-FIPS compliant algorithm '{algo}' in {file_path}")

        # Check for weak key lengths
        for algo, min_length in non_fips_patterns['key_lengths']:
            # Regex to find algorithm usage with key lengths
            pattern = f"{algo}[^0-9]*([0-9]{{1,3}})"
            if re.search(pattern, content):
                matches = re.finditer(pattern, content)
                for match in matches:
                    key_length = int(match.group(1))
                    if key_length < min_length:
                        msg = (f"Found weak key length for {algo} ({key_length} bits)"
                               f" in {file_path}")
                        print(msg)

        # Check for non-secure RNG usage
        for rng in non_fips_patterns['rngs']:
            if re.search(rng, content):
                print(f"Found non-secure RNG '{rng}' usage in {file_path}")

def search_crypto_usage(repo_path, crypto_libs, non_fips_patterns):
    """
    Recursively search through files in the given repository path to identify
    cryptographic library usage and non-FIPS compliant cryptographic practices.
    """
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                check_file_content(file_path, crypto_libs, non_fips_patterns)

def search_for_fips_references(repo_path):
    """
    Search for 'FIPS' references in code and documentation files.
    """
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.java', '.txt', '.md', '.doc', '.docx')):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    if re.search(r'\bFIPS\b', content, re.IGNORECASE):
                        print(f"Found 'FIPS' reference in {file_path}")

def main():
    """
    Parse command-line arguments for the repository path, then initiate
    the search for cryptographic usage and compliance checks.
    """
    parser = argparse.ArgumentParser(
        description='Detect cryptographic library usage and non-FIPS compliant'
                    ' practices in a Java Git repository.'
    )
    parser.add_argument('repo_path', type=str,
                        help='Path to the root directory of the Git repository')
    
    args = parser.parse_args()

    # Placeholder for cryptographic library patterns
    crypto_libs = [
        # Add your crypto library patterns here
    ]

    search_crypto_usage(args.repo_path, crypto_libs, non_fips_patterns)
    search_for_fips_references(args.repo_path)

if __name__ == '__main__':
    main()

