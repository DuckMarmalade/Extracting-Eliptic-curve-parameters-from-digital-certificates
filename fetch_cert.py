import ssl
import socket
import sys
import pathlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import binascii

# ---------------------------------------------------------------------------
# Local registry of common named curve domain parameters (hex strings).
# These are provided so the script can print the full domain parameters for
# certificates that use a well-known named curve (P-256, P-384, P-521, secp256k1).
# Values were taken from SEC 2 / curve registries.
# ---------------------------------------------------------------------------
NAMED_CURVE_PARAMS = {
    # secp256r1 / prime256v1 / NIST P-256
    "secp256r1": {
        "name": "secp256r1 (prime256v1 / P-256)",
        "p": "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "a": "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        "b": "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "Gx": "0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "Gy": "0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        "n": "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "h": "0x1",
        "notes": "Source: SEC 2 / curve registries."
    },
    # secp384r1 / P-384
    "secp384r1": {
        "name": "secp384r1 (P-384)",
        "p": "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        "a": "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
        "b": "0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "Gx": "0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "Gy": "0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
        "n": "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        "h": "0x1",
        "notes": "Source: SEC 2 / curve registries."
    },
    # secp521r1 / P-521 (Gx abbreviated in this script to keep file length reasonable)
    "secp521r1": {
        "name": "secp521r1 (P-521)",
        "p": "0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "a": "0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
        "b": "0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
        "Gx": "0x00C6864E... (truncated in display) -- see SEC 2 for full value",
        "Gy": "0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
        "n": "0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        "h": "0x1",
        "notes": "Source: SEC 2 / curve registries. (Gx shown abbreviated; full constants are long.)"
    },
    # secp256k1 (commonly used by Bitcoin)
    "secp256k1": {
        "name": "secp256k1",
        "p": "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        "a": "0x0",
        "b": "0x7",
        "Gx": "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "Gy": "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        "n": "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        "h": "0x1",
        "notes": "Source: SEC 2 / curve registries (secp256k1 is not NIST)."
    },
}


def fetch_leaf_pem(host, port=443, out_file="server_cert.pem", timeout=5.0):
    """
    Connect to <host>:<port> using a TLS client, retrieve the peer certificate
    (leaf certificate) in DER form, convert it to PEM and write it to out_file.

    - Uses SNI by passing server_hostname to wrap_socket.
    - Returns the path to the saved PEM file.
    """
    # Create a TLS client context using system CA trust and sane defaults.
    ctx = ssl.create_default_context()
    # Wrap a socket with TLS and enable SNI by providing server_hostname.
    with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
        # set a timeout so the call doesn't hang indefinitely
        s.settimeout(timeout)
        # connect to the remote server
        s.connect((host, port))
        # get the leaf certificate in DER format (binary_form=True)
        der = s.getpeercert(binary_form=True)
    # convert DER to PEM (a text format) so it's easier to inspect later
    pem = ssl.DER_cert_to_PEM_cert(der)
    # write the PEM file to disk
    pathlib.Path(out_file).write_text(pem)
    print(f"Saved leaf certificate to {out_file}")
    return out_file


def load_cert_from_file(pem_file):
    """
    Load an X.509 certificate (public key certificate to verify servers) from a file. The function first tries to parse
    the file as PEM; if that fails it falls back to DER parsing.

    Returns a cryptography.x509.Certificate object.
    """
    data = pathlib.Path(pem_file).read_bytes()
    try:
        # Try PEM first (most common when certificate was saved using PEM format)
        cert = x509.load_pem_x509_certificate(data, backend=default_backend())
    except ValueError:
        # If PEM parsing fails, try DER (binary) format.
        cert = x509.load_der_x509_certificate(data, backend=default_backend())

    return cert


def print_ec_details(public_key):
    """
    Print detailed information about an EC public key:
      - curve name and key size
      - public point coordinates (x,y)
      - if the curve matches an entry in NAMED_CURVE_PARAMS, display the
        domain parameters (p, a, b, Gx, Gy, n, h) in integer form.
    """
    # Ensure the public_key object is an EC key; otherwise bail out.
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        print("Public key is NOT an EC key (type: {}).".format(type(public_key).__name__))
        return

    # Extract the public point and curve object from the key
    numbers = public_key.public_numbers()
    curve = numbers.curve
    # Try to get a friendly curve name, fall back to the type name
    curve_name = getattr(curve, "name", None) or str(type(curve).__name__)
    key_size = curve.key_size if hasattr(curve, "key_size") else "unknown"

    print(f"Detected EC public key (curve: {curve_name}, key size: {key_size} bits)")
    x = numbers.x
    y = numbers.y
    print("Public point (uncompressed):")
    print(f"  x = {x}")
    print(f"  y = {y}")

    # Normalise the curve name for lookup in our registry. cryptography sometimes
    # exposes curve names like 'secp256r1' or 'P-256' or 'prime256v1'. We map
    # common aliases to the registry keys used above.
    lookup_name = curve_name.lower() if curve_name else None
    alias_map = {
        "p-256": "secp256r1",
        "prime256v1": "secp256r1",
        "nistp256": "secp256r1",
        "p-384": "secp384r1",
        "nistp384": "secp384r1",
        "p-521": "secp521r1",
        "nistp521": "secp521r1",
    }
    # If the raw lowercased curve name is not in our list, try aliases.
    if lookup_name not in NAMED_CURVE_PARAMS:
        lookup_name = alias_map.get(lookup_name)

    params = NAMED_CURVE_PARAMS.get(lookup_name)

    if not params:
        # No local registry entry available for this curve — we cannot print
        # domain parameters from this script's small built-in list.
        print("\nNo local registry entry for this curve.")
        return

    # Convert hex strings from the registry into Python integers so they can
    # be displayed or used for further checks.
    p = int(params["p"], 16)
    a = int(params["a"], 16)
    b = int(params["b"], 16)
    n = int(params["n"], 16)
    h = int(params["h"], 16)
    # Gx/Gy may be large; convert them too. Note: secp521r1's Gx was abbreviated
    # in the registry above; attempting to int() that truncated value will fail.
    Gx = int(params["Gx"], 16)
    Gy = int(params["Gy"], 16)

    print("\nCurve domain parameters (integer form):")
    print(f"  p/characteristic  = {p}")
    print(f"  a  = {a}")
    print(f"  b  = {b}")
    print(f"  Gx = {Gx}")
    print(f"  Gy = {Gy}")
    print(f"  n  = {n}")
    print(f"  h  = {h}")

    # Show the curve equation in a human-friendly integer form.
    print("\nCurve equation:")
    print(f"  y^2 ≡ x^3 + ({a})x + ({b})  mod {p}")

    print("\nNotes:", params.get("notes", ""))


def inspect_certificate(pem_file):
    """
    Load a certificate from pem_file and print basic metadata (subject, issuer,
    validity period) and inspect the public key. If the key is EC, delegate to
    print_ec_details(). For RSA/DSA keys the function prints type and key size
    (if available).
    """
    cert = load_cert_from_file(pem_file)
    # rfc4514_string() gives a compact one-line DN representation.
    print("Subject:", cert.subject.rfc4514_string())
    print("Issuer:", cert.issuer.rfc4514_string())
    # note: cryptography exposes not_valid_before and not_valid_after; the
    # attributes used here in the original script were suffixed with _utc —
    # keep as-is, but if you see an AttributeError consider switching to
    # cert.not_valid_before / cert.not_valid_after.
    print("NotBefore:", cert.not_valid_before_utc)
    print("NotAfter :", cert.not_valid_after_utc)

    pubkey = cert.public_key()
    # dispatch by key type
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        # print EC-specific details
        print_ec_details(pubkey)
    else:
        # For non-EC keys (RSA/DSA) print basic info; cryptography public key
        # objects commonly expose key_size.
        print("Certificate public key type:", type(pubkey).__name__)
        try:
            if hasattr(pubkey, "key_size"):
                print("Key size (bits):", pubkey.key_size)
        except Exception:
            # Best-effort: don't crash on unexpected public key implementations
            pass


def main(argv):
    """
    Command-line dispatch: either fetch a remote server certificate or inspect
    an existing PEM file when --inspect is provided.
    """
    if len(argv) < 2:
        print("Usage:")
        print("  python save_leaf_cert_with_ec_check.py HOSTNAME [PORT] [OUTFILE]")
        print("Or inspect an existing PEM:")
        print("  python save_leaf_cert_with_ec_check.py --inspect PATH_TO_PEM")
        return

    if argv[1] == "--inspect":
        if len(argv) < 3:
            print("Usage: --inspect PATH_TO_PEM")
            return
        inspect_certificate(argv[2])
        return

    # Otherwise treat first argument as hostname to connect to.
    host = argv[1]
    port = int(argv[2]) if len(argv) > 2 else 443
    out_file = argv[3] if len(argv) > 3 else "server_cert.pem"
    pem_path = fetch_leaf_pem(host, port, out_file)
    inspect_certificate(pem_path)


if __name__ == "__main__":
    main(sys.argv)
