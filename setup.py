from cx_Freeze import setup, Executable

# Detalhes do executável
executables = [Executable("trabalho2-Segurança.py")]

# Configuração do setup
setup(
    name="Trabalho2Seguranca",
    version="1.0",
    description="Servidor HTTPS com Python",
    executables=executables
)