# -----------------------------------------------
#  SneakyScan 3000 - Script tabajara para buscar conteúdo sensível
# @author Yuri Fialho
# 
# Instalação 
#
# pip install hashid 
# chmod +x scan-hash.py
# python3 ./scan-hash.py -d /etc/ -p

import os
import re
import argparse
import io
from hashid import HashID, writeResult

# Função para exibir o banner e o nome do aplicativo
def print_banner():
    banner = r'''
   ______          ___       ___       ___       ___       ___       ___
  /\_____\        /\  \     /\  \     /\  \     /\__\     /\__\     /\  \
 _\ \__/_/_      /::\  \   _\:\  \   /::\  \   /:/  /    /:/__/_   /::\  \
/\_\ \_____\    /::\:\__\ /\/::\__\ /::\:\__\ /:/__/    /::\/\__\ /:/\:\__\
\ \ \/ / / /    \/\:\/__/ \::/\/__/ \/\::/  / \:\  \    \/\::/  / \:\/:/  /
 \ \/ /\/ /        \/__/   \:\__\     /:/  /   \:\__\     /:/  /   \::/  /
  \/_/\/_/  ©2024           \/__/     \/__/     \/__/     \/__/     \/__/ 
    '''
    app_name = '''
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                Welcome to "SneakyScan 3000"
    The ultimate secret-finding ninja for your files!
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    '''
    print(banner)
    print(app_name)

# Padrões comuns para detectar senhas, tokens e hashes
patterns = {
    'password': re.compile(r'password\s*=\s*[\'"]?([a-zA-Z0-9@#\$%\^&+=]{6,})[\'"]?', re.IGNORECASE),
    'token': re.compile(r'[\w-]{20,}', re.IGNORECASE),  # Tokens como JWT, API keys
    'hash': re.compile(r'\b[0-9a-f]{32}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b', re.IGNORECASE)  # MD5, SHA1, SHA256
}

# Inicializar o Hashids
hashids = HashID()

# Função para identificar o tipo de hash usando hashid
def identify_hash_type(hash_value):

    hash_value = hash_value.lower()
    try:
        hash_type = hashids.identifyHash(hash_value)
        return hash_type
    except Exception as e:
        print(e)
        return "Indefinido"

# Função para adicionar palavras-chave informadas pelo usuário ao padrão
def add_custom_keywords(keywords):
    if keywords:
        keyword_pattern = re.compile(r'|'.join(re.escape(keyword) for keyword in keywords), re.IGNORECASE)
        patterns['custom_keywords'] = keyword_pattern

# Função para varrer arquivos em busca dos padrões
def search_sensitive_data(file_path):
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            for key, pattern in patterns.items():
                matches = pattern.findall(content)
                if matches:
                    results.append((key, matches))
    except Exception as e:
        print(f"Erro ao abrir o arquivo {file_path}: {e}")
    
    return results

# Função para varrer diretórios
def scan_directory(directory, print_hashes):
    if not os.path.isdir(directory):
        print(f"[ERRO] O diretório especificado não é válido: {directory}")
        return
    found=False
    print("[RESULTADO]")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            results = search_sensitive_data(file_path)
            if results:
                found=True
                print(f"File: {file_path}")
                for key, matches in results:
                    # Controla a impressão de hashes
                    if not print_hashes:
                        continue
                    print(f"Tipo: {key}")
                    for match in matches:
                        if key == 'hash':
                            hash_type = identify_hash_type(match)
                            buffer = io.StringIO()
                            writeResult(hash_type,buffer)
                            output_hash_type = extract_first_item(buffer.getvalue())
                            print(f" - {match} (Tipo: {output_hash_type})")
                            buffer.close()
                        else:
                            print(f" - {match}")
    if not found:
        print('Não foi encontrado nenhum registro')

def extract_first_item(text):
    # Usar expressão regular para encontrar o primeiro item
    match = re.search(r'\[\+\]\s*([^\[\+]+)', text)
    if match:
        return match.group(1).strip()  # Retorna o primeiro item encontrado, removendo espaços extras
    return "Nao identificado"  # Retorna None se nenhum item for encontrado

# Função para processar os argumentos da linha de comando
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Varredura de arquivos em busca de senhas, tokens, hashes e palavras-chave.",
        epilog="Exemplo de uso: python scan_script.py -d /path/to/dir -w keyword1,keyword2 --no-print-hashes"
    )
    
    parser.add_argument(
        '-d', '--dir',
        type=str,
        required=True,
        help="Especifica o diretório a ser escaneado. Use '.' para o diretório corrente."
    )
    
    parser.add_argument(
        '-w', '--words',
        type=str,
        help="Palavras-chave separadas por vírgulas para buscar nos arquivos. Exemplo: -w senha,token"
    )
    
    parser.add_argument(
        '-p','--print-hash',
        action='store_false',
        help="Desativa a impressão dos hashes encontrados (eles ainda serão buscados)."
    )

    # argparse automaticamente lida com -h ou --help
    args = parser.parse_args()
    return args.dir, args.words, args.print_hash

# Entrada principal
if __name__ == '__main__':
    # Exibe o banner e o nome do aplicativo no início
    print_banner()

    # Parsear argumentos da linha de comando
    directory_to_scan, keywords_input, print_hash = parse_arguments()

    # Garantir que o diretório seja tratado corretamente
    if directory_to_scan == ".":
        directory_to_scan = os.getcwd()

    # Processar palavras-chave fornecidas como argumento
    keywords = [keyword.strip() for keyword in keywords_input.split(',')] if keywords_input else []
    
    # Adicionar as palavras-chave informadas pelo usuário ao padrão
    add_custom_keywords(keywords)

    # Escanear o diretório fornecido, controlando a impressão de hashes
    scan_directory(directory_to_scan, print_hashes=not print_hash)
