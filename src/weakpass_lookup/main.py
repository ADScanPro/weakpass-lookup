#!/usr/bin/env python3
import argparse
import requests
import sys
import os
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional
from tqdm import tqdm

# Variable global para el modo verbose
VERBOSE = False

def log(message: str):
    """Imprime mensajes de depuración si el modo verbose está activado."""
    if VERBOSE:
        print(message)

def check_hash_with_type(hash_value: str, hash_type: str) -> Tuple[str, Optional[str]]:
    """
    Consulta un hash en la API de Weakpass usando el endpoint de range con tipo específico.
    Retorna una tupla (hash, password o None).
    """
    try:
        prefix = hash_value[:5]
        url = f"https://weakpass.com/api/v1/range/{prefix}"
        params = {'type': hash_type}
        log(f"Consultando {url} con params {params} para el hash {hash_value}")
        
        response = requests.get(url, params=params)
        log(f"Respuesta HTTP: {response.status_code} para el hash {hash_value}")
        if response.status_code == 200:
            results = response.json()
            # Buscamos el hash completo en los resultados
            for result in results:
                if result['hash'].lower() == hash_value.lower():
                    log(f"Hash encontrado: {hash_value} -> {result['pass']}")
                    return (hash_value, result['pass'])
            # Si no encontramos el hash en los resultados, lo marcamos como no crackeado
            return (hash_value, None)
        elif response.status_code == 404:
            # Si no hay resultados para ese prefijo, el hash no está crackeado
            return (hash_value, None)
        else:
            print(f"\nError al consultar el hash {hash_value}: {response.status_code}")
            return (hash_value, None)
    except Exception as e:
        print(f"\nError en la petición para el hash {hash_value}: {str(e)}")
        return (hash_value, None)

def check_hash_generic(hash_value: str) -> Tuple[str, Optional[str]]:
    """
    Consulta un hash en la API de Weakpass usando el endpoint de búsqueda genérica.
    Retorna una tupla (hash, password o None).
    """
    try:
        url = f"https://weakpass.com/api/v1/search/{hash_value}"
        log(f"Consultando {url} para el hash {hash_value}")
        
        response = requests.get(url)
        log(f"Respuesta HTTP: {response.status_code} para el hash {hash_value}")
        if response.status_code == 200:
            results = response.json()
            if results and len(results) > 0:
                log(f"Hash encontrado: {hash_value} -> {results[0]['pass']}")
                return (hash_value, results[0]['pass'])
            # Si la respuesta está vacía, el hash no está crackeado
            return (hash_value, None)
        elif response.status_code == 404:
            # Si no se encuentra el hash, lo marcamos como no crackeado
            return (hash_value, None)
        else:
            print(f"\nError al consultar el hash {hash_value}: {response.status_code}")
            return (hash_value, None)
    except Exception as e:
        print(f"\nError en la petición para el hash {hash_value}: {str(e)}")
        return (hash_value, None)

def validate_hash(hash_value: str, hash_type: str = None) -> bool:
    """
    Valida el formato del hash según su tipo.
    """
    if not all(c in '0123456789abcdefABCDEF' for c in hash_value):
        return False
        
    if hash_type:
        expected_lengths = {
            'md5': 32,
            'ntlm': 32,
            'sha1': 40,
            'sha256': 64
        }
        return len(hash_value) == expected_lengths.get(hash_type)
    else:
        # Para búsqueda genérica, aceptamos hashes entre 32 y 64 caracteres
        return 32 <= len(hash_value) <= 64

def process_hash(hash_value: str, hash_type: str = None) -> Tuple[str, Optional[str]]:
    """
    Procesa un único hash usando el método apropiado según el tipo.
    Siempre retorna una tupla (hash, password o None).
    """
    log(f"Iniciando procesamiento del hash {hash_value} con tipo {hash_type or 'genérico'}")
    try:
        if hash_type:
            result = check_hash_with_type(hash_value, hash_type)
        else:
            result = check_hash_generic(hash_value)
        log(f"Finalizado procesamiento del hash {hash_value}")
        return result
    except Exception as e:
        print(f"\nError inesperado procesando hash {hash_value}: {str(e)}")
        return (hash_value, None)

def process_single_hash(hash_value: str, hash_type: str = None):
    """
    Procesa un único hash y muestra el resultado en pantalla.
    """
    if not validate_hash(hash_value, hash_type):
        print(f"Error: Hash con formato inválido para el tipo {hash_type or 'genérico'}")
        sys.exit(1)
    
    print(f"Procesando hash{f' tipo {hash_type}' if hash_type else ''}: {hash_value}")
    result = process_hash(hash_value, hash_type)
    
    if result[1] is not None:
        print(f"\nHash crackeado: {result[0]}:{result[1]}")
    else:
        print(f"\nHash no encontrado: {result[0]}")

def process_hashes(input_file: str, hash_type: str = None, workers: int = 1):
    """
    Procesa un archivo de hashes usando múltiples threads.
    """
    base_name = os.path.splitext(input_file)[0]
    cracked_file = f"{base_name}_cracked.txt"
    uncracked_file = f"{base_name}_uncracked.txt"
    
    try:
        with open(input_file, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]
        log(f"Se han leído {len(hashes)} hashes desde el archivo {input_file}")
    except FileNotFoundError:
        print(f"Error: No se encuentra el archivo {input_file}")
        sys.exit(1)
    
    # Validamos el formato de los hashes
    invalid_hashes = [h for h in hashes if not validate_hash(h, hash_type)]
    if invalid_hashes:
        print(f"Error: Se encontraron hashes con formato inválido para el tipo {hash_type or 'genérico'}:")
        for h in invalid_hashes:
            print(f"- {h}")
        sys.exit(1)
    
    total = len(hashes)
    cracked = []
    uncracked = []
    
    print(f"Procesando {total} hashes{f' tipo {hash_type}' if hash_type else ''} usando {workers} threads...")
    
    # Procesamiento en paralelo usando ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Creamos las tareas para cada hash
        futures = [executor.submit(process_hash, hash_value, hash_type) for hash_value in hashes]
        
        # Procesamos los resultados usando tqdm para mostrar el progreso
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Procesando"):
            try:
                result = future.result()
                if result is None:
                    continue
                hash_value, password = result
                if password is not None:
                    cracked.append(f"{hash_value}:{password}")
                else:
                    uncracked.append(hash_value)
            except Exception as e:
                print(f"\nError procesando resultado: {str(e)}")
                continue
    
    # Guardamos los resultados
    with open(cracked_file, 'w') as f:
        f.write('\n'.join(cracked) + '\n' if cracked else '')
    
    with open(uncracked_file, 'w') as f:
        f.write('\n'.join(uncracked) + '\n' if uncracked else '')
    
    print("\nResultados:")
    print(f"Total de hashes procesados: {total}")
    print(f"Hashes crackeados: {len(cracked)}")
    print(f"Hashes no crackeados: {len(uncracked)}")
    print(f"\nResultados guardados en:")
    print(f"- Crackeados: {cracked_file}")
    print(f"- No crackeados: {uncracked_file}")

def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description='Busca hashes en la API de Weakpass')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='Archivo con lista de hashes (uno por línea)')
    group.add_argument('-H', '--hash', help='Hash individual para buscar')
    parser.add_argument('-t', '--type', choices=['md5', 'ntlm', 'sha1', 'sha256'], 
                        help='Tipo de hash (opcional, si no se especifica se usa búsqueda genérica)')
    parser.add_argument('-w', '--workers', type=int, default=10,
                        help='Número de threads a utilizar (por defecto: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Modo verbose para mostrar más detalles de depuración')
    
    args = parser.parse_args()
    VERBOSE = args.verbose  # Activamos el modo verbose si se indica
    
    if args.file:
        process_hashes(args.file, args.type, args.workers)
    else:
        process_single_hash(args.hash, args.type)

if __name__ == "__main__":
    main()