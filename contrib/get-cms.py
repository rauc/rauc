#!/usr/bin/env python3

import argparse
import os


def extract_cms(bundle_path):
    with open(bundle_path, "rb") as bundle_file:
        # Move to the end of the bundle to read the last 8 bytes for the CMS length
        bundle_file.seek(-8, os.SEEK_END)
        cms_length_bytes = bundle_file.read(8)

        # Convert the 8 bytes to an integer representing the CMS length
        cms_length = int.from_bytes(cms_length_bytes, "big")
        print(f"CMS length is {cms_length} bytes.")

        # Seek to the start of the CMS (8 + length bytes from the end)
        bundle_file.seek(-(8 + cms_length), os.SEEK_END)

        # Read the CMS
        cms = bundle_file.read(cms_length)

        return cms


def main():
    parser = argparse.ArgumentParser(description="extract the CMS from a RAUC bundle")
    parser.add_argument("input", type=str, help="input bundle")
    parser.add_argument("output", type=str, help="output filename")

    args = parser.parse_args()

    # Read from the bundle
    cms = extract_cms(args.input)

    # Write to a new file
    with open(args.output, "wb") as cms_file:
        cms_file.write(cms)

    msg = f"""CMS written to '{args.output}'. You can now...

    print the CMS data structure:
    $ openssl cms -cmsout -in {args.output} -inform DER -print

    skip the signature verification and print the manifest (verity format):
    $ openssl cms -verify -in {args.output} -inform DER -noverify

    verify the signature and print the manifest (verity format):
    $ openssl cms -verify -in {args.output} -inform DER -CAfile <your_ca.pem>

    decrypt, verify and print the manifest (crypt format):
    $ openssl cms -decrypt -in {args.output} -inform DER -inkey <your_key.pem> |
      openssl cms -verify -inform DER -CAfile <your_ca.pem>
    """.rstrip()
    print(msg)


if __name__ == "__main__":
    main()
