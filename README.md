![UNIVERSIDADE DE BRASÍLIA](https://psicc.unb.br/wp-content/uploads/2023/07/logounb.fw_-2048x174.png)

DEPARTAMENTO DE CIÊNCIA DA COMPUTAÇÃO\
DISCIPLINA DE SEGURANÇA DA COMPUTAÇÃO

# TRABALHO PRÁTICO 2 - protocol HTTPS over TLS

_MEMBROS:VINÍCIUS BOWEN - 180079239_\
_RAMON OLIVEIRA - 242039630_\

---

# **Sumário**

1. **Pesquisa e Detalhamento dos Protocolos de Segurança**\
   1.1. Introdução ao HTTPS, SSL e TLS\
   1.2. Objetivos e funcionalidades dos protocolos\
   1.3. Processos de criptografia, autenticação e troca de chaves\
   1.4. Evolução das versões e comparação entre elas

2. **Implementação do Servidor e Cliente HTTPS**\
   2.1. Visão geral da arquitetura cliente/servidor\
   2.2. Utilização do OpenSSL e outras bibliotecas de segurança\
   2.3. Implementação prática e explicação do código\
   2.4. Testes e análise de comunicação segura\
   2.5. Preenchimento dos Campos do Certificado

3. **Conclusão e Análise Final**\
   3.1. Impacto dos protocolos na segurança da web\
   3.2. Benefícios e limitações da implementação\
   3.3. Possíveis melhorias e extensões

---

# **Abstract: Implementação do Servidor e Cliente HTTPS**

A segurança na comunicação entre cliente e servidor é um dos principais desafios no desenvolvimento de aplicações web. O protocolo HTTPS (HyperText Transfer Protocol Secure) surge como uma solução garantindo confidencialidade, integridade e autenticidade dos dados transmitidos. Para compreender melhor seu funcionamento, este relatório apresenta a implementação de um servidor e cliente HTTPS utilizando a linguagem Python, explorando bibliotecas como `http.server`, `ssl` e `cryptography`. Além da implementação prática, são descritas estratégias de validação e testes da comunicação segura, utilizando ferramentas como OpenSSL e Wireshark.

# **1. Introdução: Pesquisa dos Protocolos de Segurança**

## **1.1. Detalhamento do HTTPS, SSL e TLS**

## **SSL (Secure Sockets Layer) e TLS (Transport Layer Security)**

O SSL e seu sucessor, TLS, são protocolos essenciais para garantir a segurança das comunicações na internet. Eles utilizam criptografia para proteger dados transmitidos entre clientes e servidores, impedindo que terceiros acessem informações sensíveis como senhas e dados financeiros.

### **Objetivos e Funcionalidades Gerais**

O SSL foi desenvolvido para garantir a segurança das comunicações na internet, criptografando os dados transmitidos entre um navegador e um servidor. O TLS surgiu como sua evolução, aprimorando a segurança e corrigindo vulnerabilidades.

Os principais objetivos desses protocolos são:

- **Confidencialidade**: Utilizam criptografia simétrica e assimétrica para evitar que os dados sejam interceptados.
- **Autenticação**: Certificados digitais asseguram que o servidor (e, em alguns casos, o cliente) é legítimo.
- **Integridade dos Dados**: Algoritmos de hash garantem que os dados não foram alterados durante a transmissão.

### **Etapas de Segurança e Principais Algoritmos**

1. **Criptografia**: Usa algoritmos como AES (Advanced Encryption Standard), ChaCha20 e 3DES para criptografar os dados transmitidos.
2. **Autenticação**: Certificados digitais X.509 são utilizados para autenticar a identidade do servidor e, opcionalmente, do cliente.
3. **Troca de Chaves**: Utiliza o algoritmo Diffie-Hellman, ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) ou RSA para estabelecer uma chave de sessão segura. Essa troca de chave pode sofrer um "padding" utilizando uma técnica como o OEAP.
4. **Integridade dos Dados**: Funções hash como SHA-256 garantem que os dados não foram modificados durante a transmissão.

### **Resumo das Versões e Evolução**

- **SSL 1.0**: Nunca foi lançado publicamente devido a falhas de segurança.
- **SSL 2.0**: Lançado em 1995, mas rapidamente substituído devido a vulnerabilidades.
- **SSL 3.0**: Lançado em 1996, trouxe melhorias, mas foi considerado inseguro com o tempo.
- **TLS 1.0** (1999): Primeira versão do TLS, substituiu o SSL 3.0.
- **TLS 1.1** (2006): Melhorou a segurança contra ataques de injeção de pacotes.
- **TLS 1.2** (2008): Introduziu novos algoritmos de criptografia e hash mais seguros.
- **TLS 1.3** (2018): Tornou o handshake mais eficiente e removeu algoritmos inseguros.

## **1.2. HTTPS (HyperText Transfer Protocol Secure)**

O HTTPS é a versão segura do HTTP, utilizando SSL ou TLS para criptografar a comunicação entre o navegador e o servidor. Esse protocolo garante que os dados transmitidos sejam confidenciais e íntegros, protegendo contra ataques de interceptação e manipulação, como os ataques Man in the Middle. Atualmente, mais de 80% dos sites na web utilizam TLS para garantir a segurança das comunicações. O protocolo HTTPS utiliza algoritmos de criptografia robustos, como RSA, para assegurar que apenas o destinatário pretendido possa ler a mensagem, mantendo a privacidade e a integridade dos dados transmitidos.

O HTTPS evoluiu junto com os protocolos SSL e TLS, adotando as melhorias de cada versão para oferecer mais segurança e desempenho.

---

# **2. Implementação do Servidor e Cliente HTTPS**
## **2.1. Visão Geral da Arquitetura Cliente/Servidor**

A comunicação segura entre um cliente e um servidor HTTPS envolve a troca de informações criptografadas utilizando o protocolo TLS. O fluxo básico dessa comunicação é:

1. O cliente estabelece conexão com o servidor via HTTPS.
2. O servidor apresenta seu certificado digital (SSL/TLS).
3. O cliente verifica a autenticidade do certificado.
4. O cliente e o servidor realizam um handshake TLS para troca de chaves seguras.
5. A comunicação entre cliente e servidor ocorre de forma criptografada.

## **2.2. Utilização do OpenSSL e Outras Bibliotecas de Segurança**

Para implementar um servidor e cliente HTTPS, utilizaremos **Python** com as bibliotecas:

- `http.server` e `ssl` para criar o servidor HTTPS.
- `requests` e `socket` para implementar o cliente HTTPS.
- `cryptography` para geração de certificados SSL/TLS via código.
- `datetime`: Usado para definir o período de validade do certificado.

## **2.3. Implementação Prática e Explicação do Código**

A seguir, mostramos a implementação do servidor HTTPS em Python:

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
```
2.3. Implementação Prática e Explicação do Código


### **Compilação e Execução do Código**

Para rodar o servidor HTTPS, execute o seguinte comando no terminal dentro do diretório onde o script Python está salvo:

```sh
python nome_do_arquivo.py
```

Isso iniciará o servidor e exibirá uma mensagem confirmando sua execução:

```
Servidor HTTPS rodando em https://localhost:4443
```

Agora o servidor está ouvindo conexões seguras na porta 4443.

### **Acessando o Servidor pelo Navegador**

1. Abra um navegador e acesse: `https://localhost:4443`

2.Como o certificado é autoassinado, o navegador exibirá um aviso de segurança.

3. Clique em **Avançado** e prossiga para o site.

4. O servidor retornará a resposta HTTP segura configurada no código.

### **Instalação do OpenSSL**

Para instalar o OpenSSL em sistemas baseados em Linux (Ubuntu/Debian), utilize:

```sh
sudo apt update && sudo apt install openssl
```

Para verificar se a instalação foi bem-sucedida, execute:

```sh
openssl version
```

Se o OpenSSL estiver instalado corretamente, ele retornará a versão do software.

### **Wireshark: Analisando o Tráfego TLS**

O Wireshark é uma ferramenta de análise de pacotes que permite inspecionar o tráfego TLS do servidor HTTPS. Para instalar:

```sh
sudo apt update && sudo apt install wireshark
```

Durante a instalação, selecione **Sim** para permitir que usuários não-root capturem pacotes.

Para verificar a instalação:

```sh
wireshark --version
```

Essas etapas garantem que o servidor está configurado corretamente e que a comunicação segura está funcionando.

---

# **2.5. Preenchimento dos Campos do Certificado**

[IMAGEM DO CERTIFICADO PRINT DA TELA DO NAVEGADOR]

Ao criar um certificado digital, diversos campos podem ser preenchidos para garantir a correta identificação da entidade proprietária do certificado. Esses campos são essenciais para assegurar autenticidade e confiança na comunicação segura. Abaixo, explicamos os principais campos e sua importância:

- **C = Country (País)** → Indica o país onde a organização ou entidade está registrada. Exemplo: `BR` para Brasil.
- **ST = State/Province (Estado ou Província)** → Especifica o estado ou província dentro do país. Exemplo: `Distrito Federal`.
- **L = Locality (Cidade ou Localidade)** → Define a cidade onde a entidade está localizada. Exemplo: `Brasília`.
- **O = Organization (Organização)** → Nome da empresa ou entidade proprietária do certificado. Exemplo: `Universidade de Brasília`.
- **OU = Organizational Unit (Unidade Organizacional)** → Usado para definir um departamento dentro da organização. Exemplo: `TI`.
- **CN = Common Name (Nome Comum)** → Define o domínio ou nome da entidade que usará o certificado. Exemplo: `localhost` ou `sti.unb.br`.

Como este é um trabalho da disciplina de segurança computacional, o certificado gerado não é válido para HTTPS em um ambiente real. Para que um certificado seja considerado válido, ele deve ser emitido por uma Autoridade Certificadora (CA) confiável, como a ICP-Brasil no Brasil ou a DigiCert internacionalmente. Cada navegador vem de fábrica com uma lista de autoridades certificadoras confiáveis e verifica a autenticidade do certificado através do protocolo TLS. Isso garante que o site acessado pelo usuário é certificado e que o tráfego é criptografado utilizando TLS e RSA, assegurando a confidencialidade e integridade dos dados transmitidos.

Os certificados TLS são fundamentais para a segurança na web. Eles são usados para estabelecer conexões seguras entre clientes e servidores, garantindo que os dados transmitidos sejam criptografados e protegidos contra interceptações. Um certificado TLS contém informações sobre a identidade do servidor, a chave pública usada para criptografia e a assinatura digital da CA que emitiu o certificado. Quando um navegador se conecta a um site HTTPS, ele verifica o certificado apresentado pelo servidor contra a lista de CAs confiáveis. Se o certificado for válido, a conexão segura é estabelecida, permitindo a troca de dados de forma segura e protegida.

---

# **3. Conclusão e Análise Final**

A implementação do HTTPS melhora significativamente a segurança das aplicações web, garantindo a confidencialidade, integridade e autenticidade dos dados. Apesar dos desafios na configuração e implementação, o uso de certificados autoassinados permitiu um entendimento mais aprofundado sobre a criptografia na web. Futuramente, melhorias como a integração com autoridades certificadoras podem ser exploradas para aumentar a confiabilidade da solução.