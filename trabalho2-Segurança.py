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
    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "BR"),  # País
    x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Distrito Federal"),  # Estado
    x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Brasília"),  # Cidade
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Universidade de Brasília"),  # Organização
    x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "STI"),  # Unidade Organizacional
    x509.NameAttribute(x509.NameOID.COMMON_NAME, "sti.unb.br"),  # Nome Comum (domínio)
])

# Constrói o certificado com as informações fornecidas
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)  # Define o nome do sujeito
    .issuer_name(issuer)  # Define o nome do emissor (autoassinado, então é o mesmo que o sujeito)
    .public_key(key.public_key())  # Define a chave pública
    .serial_number(x509.random_serial_number())  # Define um número de série aleatório
    .not_valid_before(datetime.datetime.utcnow())  # Define a data de início da validade
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # Define a data de término da validade (1 ano)
    .sign(key, hashes.SHA256())  # Assina o certificado com a chave privada e o algoritmo SHA-256
)

# Salva a chave privada e o certificado em arquivos
for filename, data in [("key.pem", key.private_bytes(
    encoding=serialization.Encoding.PEM,  # Codificação PEM
    format=serialization.PrivateFormat.TraditionalOpenSSL,  # Formato tradicional do OpenSSL
    encryption_algorithm=serialization.NoEncryption())),  # Sem criptografia para a chave privada
    ("cert.pem", cert.public_bytes(serialization.Encoding.PEM))]:  # Certificado em formato PEM
    with open(filename, "wb") as f:
        f.write(data)  # Escreve os dados no arquivo

# Configura o servidor HTTPS
server_address = ('localhost', 4443)  # Define o endereço do servidor (localhost) e a porta (4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)  # Cria o servidor HTTP

# Configura o contexto SSL
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Cria um contexto SSL para o servidor
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")  # Carrega o certificado e a chave privada

# Envolve o socket do servidor com o contexto SSL
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

# Inicia o servidor HTTPS
print("Servidor HTTPS rodando em https://localhost:4443")
httpd.serve_forever()  # Mantém o servidor rodando indefinidamente