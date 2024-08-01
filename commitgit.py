from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime

# Générer une clé privée RSA
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Créer un nom X.509
name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u'localhost'),
])

# Générer un certificat auto-signé
cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    # Le certificat est valide pour 365 jours
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).sign(key, hashes.SHA256(), default_backend())

# Enregistrer la clé privée dans un fichier PEM
with open("key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Enregistrer le certificat dans un fichier PEM
with open("cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))