#!/usr/bin/env python3

import inspect
from pyasn1.codec.der import decoder
from pyasn1.type import univ, char
from pyasn1_modules import rfc2315, rfc5280, rfc5480, rfc5652


def build_oid_map(modules):
    oid_map = {}
    for module in modules:
        for name, obj in inspect.getmembers(module):
            if isinstance(obj, univ.ObjectIdentifier):
                oid_str = str(obj)
                name = name.removeprefix("id_")
                oid_map[oid_str] = name
    return oid_map


OID_MAP = build_oid_map([rfc2315, rfc5280, rfc5480, rfc5652])


def resolve_oid(oid):
    return OID_MAP.get(str(oid), oid)


def decode_as_string(value_any):
    for asn1_type in [char.PrintableString, char.UTF8String]:
        try:
            decoded, _ = decoder.decode(value_any.asOctets(), asn1Spec=asn1_type())
            return str(decoded)
        except Exception:
            continue
    # fallback: return hex
    return value_any.prettyPrint()


def name_to_string(name):
    parts = []
    seq = name.getComponentByName("rdnSequence")
    for rdn in seq:  # each rdn is a SET OF AttributeTypeAndValue
        if isinstance(rdn, str):
            continue
        for attr in rdn:
            type_oid = attr.getComponentByName("type")
            value = attr.getComponentByName("value")
            value_str = decode_as_string(value)

            oid_map = {
                "2.5.4.3": "CN",
                "2.5.4.10": "O",
            }

            oid_str = str(type_oid)
            name = oid_map.get(oid_str, oid_str)

            parts.append(f"{name}={value_str}")

    return ", ".join(parts)


def decode_cms_signed_data(content_info):
    result = {}

    signed_data, _ = decoder.decode(content_info.getComponentByName("content"), asn1Spec=rfc5652.SignedData())

    result["digestAlgorithms"] = []
    for algo in signed_data.getComponentByName("digestAlgorithms"):
        result["digestAlgorithms"].append(resolve_oid(algo.getComponentByName("algorithm")))

    eci = signed_data.getComponentByName("encapContentInfo")
    content_type = eci.getComponentByName("eContentType")
    content = eci.getComponentByName("eContent")

    result["eContentType"] = resolve_oid(content_type)
    if content is not None and content.isValue:
        result["eContent"] = bytes(content)
    else:
        result["eContent"] = None

    certs = signed_data.getComponentByName("certificates")
    result["certs"] = []
    if certs is not None:
        for cert_choice in certs:
            if cert_choice.getName() == "certificate":
                cert = cert_choice.getComponent()
                tbs_cert = cert.getComponentByName("tbsCertificate")
                serial = tbs_cert.getComponentByName("serialNumber")
                issuer = tbs_cert.getComponentByName("issuer")
                subject = tbs_cert.getComponentByName("subject")
                result["certs"].append(
                    {
                        # all our certificates have serial numbers, so we can just convert here
                        "serial": int(serial),
                        "issuer": name_to_string(issuer),
                        "subject": name_to_string(subject),
                    }
                )

    signer_infos = signed_data.getComponentByName("signerInfos")
    result["signerInfos"] = []
    for signer_info in signer_infos:
        sid = signer_info.getComponentByName("sid")
        if sid.getName() == "issuerAndSerialNumber":
            iasn = sid.getComponent()  # get SEQUENCE inside the CHOICE
            issuer = iasn.getComponentByName("issuer")
            serial = iasn.getComponentByName("serialNumber")
        else:
            issuer = None
            serial = None
        digest_algorithm = signer_info.getComponentByName("digestAlgorithm")
        sig_algorithm = signer_info.getComponentByName("signatureAlgorithm")
        signature = signer_info.getComponentByName("signature")
        result["signerInfos"].append(
            {
                "issuer": name_to_string(issuer),
                "serial": int(serial),
                "digestAlgorithm": resolve_oid(digest_algorithm.getComponentByName("algorithm")),
                "signatureAlgorithm": resolve_oid(sig_algorithm.getComponentByName("algorithm")),
                "signature": bytes(signature),
            }
        )

    return result


def decode_cms_enveloped_data(content_info):
    result = {}

    enveloped_data, _ = decoder.decode(content_info.getComponentByName("content"), asn1Spec=rfc5652.EnvelopedData())

    eci = enveloped_data.getComponentByName("encryptedContentInfo")
    content_type = eci.getComponentByName("contentType")
    content = eci.getComponentByName("encryptedContent")

    result["contentType"] = resolve_oid(content_type)
    if content is not None and content.isValue:
        result["encryptedContent"] = bytes(content)
    else:
        result["encryptedContent"] = None

    return result


def decode_cms(der_data):
    content_info, _ = decoder.decode(der_data, asn1Spec=rfc5652.ContentInfo())

    content_type = content_info.getComponentByName("contentType")
    if content_type == rfc5652.id_signedData:
        result = decode_cms_signed_data(content_info)
    elif content_type == rfc5652.id_envelopedData:
        result = decode_cms_enveloped_data(content_info)
    else:
        raise ValueError("Not a supported CMS message.")

    return {
        "contentType": resolve_oid(content_type),
        **result,
    }


def main():
    import argparse
    import sys
    from pprint import pprint

    parser = argparse.ArgumentParser(
        description="Decode a CMS (Cryptographic Message Syntax) DER file and pretty-print its contents."
    )
    parser.add_argument("input_file", help="Path to the DER-encoded CMS file to decode.")

    args = parser.parse_args()

    try:
        with open(args.input_file, "rb") as f:
            der_data = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {args.input_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file {args.input_file}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        result = decode_cms(der_data)
        pprint(result, sort_dicts=False)
    except Exception as e:
        print(f"Error decoding CMS data: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
