"""Self-signed CA:TRUE certificate for 127.0.0.1, like README's platform cert: cert.pem + key.pem in <dir>.

    python make_cert.py <dir>        (needs the cryptography package)
"""
import datetime
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=2))
    .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=True,
                                 content_commitment=False, data_encipherment=False, key_agreement=False,
                                 crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    .sign(key, hashes.SHA256())
)
(out / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(out / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
print("wrote", out / "cert.pem")
