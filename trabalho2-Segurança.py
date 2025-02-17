import http.server
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Gera uma chave privada RSA de 2048 bits
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Cria um certificado autoassinado válido por 1 ano
subject = issuer = x509.Name([
    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "BR"),
    x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Distrito Federal"),
    x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Brasília"),
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Universidade de Brasília"),
    x509.NameAttribute(x509.NameOID.COMMON_NAME, "sti.unb.br"),
])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .sign(key, hashes.SHA256())
)

# Salva chave privada e certificado em arquivos
for filename, data in [("key.pem", key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())),
    ("cert.pem", cert.public_bytes(serialization.Encoding.PEM))]:
    with open(filename, "wb") as f:
        f.write(data)

# Configura o servidor HTTPS
server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

# Configura o contexto SSL
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Servidor HTTPS rodando em https://localhost:4443")
httpd.serve_forever()