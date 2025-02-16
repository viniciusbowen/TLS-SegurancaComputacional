# **Sumário**

1. **Implementação do Servidor e Cliente HTTPS**\
   1.1. Visão geral da arquitetura cliente/servidor\
   1.2. Utilização do OpenSSL e outras bibliotecas de segurança\
   1.3. Implementação prática e explicação do código\
   1.4. Testes e análise de comunicação segura

2. **Roteiro para Implementação**\
   2.1. Objetivos do projeto\
   2.2. Tecnologias e bibliotecas utilizadas\
   2.3. Estrutura geral do código\
   2.4. Estratégia de testes e validação\
   2.5. Entregáveis e critérios de avaliação

3. **Pesquisa e Detalhamento dos Protocolos de Segurança**\
   3.1. Introdução ao HTTPS, SSL e TLS\
   3.2. Objetivos e funcionalidades dos protocolos\
   3.3. Processos de criptografia, autenticação e troca de chaves\
   3.4. Evolução das versões e comparação entre elas

4. **Conclusão e Análise Final**\
   4.1. Impacto dos protocolos na segurança da web\
   4.2. Benefícios e limitações da implementação\
   4.3. Possíveis melhorias e extensões

---

# **1. Implementação do Servidor e Cliente HTTPS**

## **1.1. Visão Geral da Arquitetura Cliente/Servidor**

A comunicação segura entre um cliente e um servidor HTTPS envolve a troca de informações criptografadas utilizando o protocolo TLS. O fluxo básico dessa comunicação é:

1. O cliente estabelece conexão com o servidor via HTTPS.
2. O servidor apresenta seu certificado digital (SSL/TLS).
3. O cliente verifica a autenticidade do certificado.
4. O cliente e o servidor realizam um handshake TLS para troca de chaves seguras.
5. A comunicação entre cliente e servidor ocorre de forma criptografada.

## **1.2. Utilização do OpenSSL e Outras Bibliotecas de Segurança**

Para implementar um servidor e cliente HTTPS, utilizaremos **Python** com as bibliotecas:

- `http.server` e `ssl` para criar o servidor HTTPS.
- `requests` e `socket` para implementar o cliente HTTPS.
- `cryptography` para geração de certificados SSL/TLS via código.

## **1.3. Implementação Prática e Explicação do Código**

### **Importação das Bibliotecas**

- `http.server` e `ssl`: Usadas para criar o servidor HTTPS e aplicar criptografia na comunicação.
- `cryptography`: Biblioteca que permite gerar certificados e chaves criptográficas diretamente em Python.
- `datetime`: Usado para definir o período de validade do certificado.

### **Código do Servidor HTTPS**

```python
import http.server
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Gera uma chave privada RSA de 2048 bits
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Cria um certificado autoassinado válido por 1 ano
cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")]))
    .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")]))
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

# Aplica o certificado SSL ao servidor
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="cert.pem", keyfile="key.pem", server_side=True)

print("Servidor HTTPS rodando em https://localhost:4443")
httpd.serve_forever()
```

## **1.4. Testes e Análise de Comunicação Segura**

### **Rodando o servidor**
Para iniciar o servidor HTTPS, execute o seguinte comando no terminal:
```sh
python nome_do_arquivo.py
```

### **Testando com um navegador**
1. Abra um navegador e acesse: [https://localhost:4443](https://localhost:4443)
2. Como o certificado é autoassinado, o navegador exibirá um aviso de segurança. Prossiga para visualizar a página.

### **Testando com cURL**
No terminal, use o seguinte comando:
```sh
curl -k https://localhost:4443
```
O parâmetro `-k` permite ignorar a verificação do certificado autoassinado.

### **Verificando o certificado**
Para inspecionar o certificado gerado, execute:
```sh
openssl x509 -in cert.pem -text -noout
```
Isso exibirá detalhes sobre o certificado, como emissor, validade e algoritmo de assinatura.

