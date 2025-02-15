import http.server
import ssl

server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

# Configura o SSL com um certificado e chave privada
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='cert.pem', keyfile='key.pem', server_side=True)

print("Servidor HTTPS rodando em https://localhost:4443")
httpd.serve_forever()