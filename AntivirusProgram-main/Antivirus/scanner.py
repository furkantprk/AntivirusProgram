import os
import hashlib
import shutil
import sqlite3
import json

#Belirtilen klasördeki tüm dosyaları ve alt klasörlerdeki dosyaları bulur.
def get_all_files(directory):

    for root, _, files in os.walk(directory):
        for file in files:
            yield os.path.join(root, file)

#Bir dosyanın hash değerini hesaplar.
def calculate_hash(file_path, algorithm='md5'):

    try:
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):  # 4KB parça parça oku
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

#SQLite veritabanından virüs hash'lerini yükler.
def load_virus_database(db_file):

    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT hash FROM VirusHashDB")
        virus_hashes = [row[0] for row in cursor.fetchall()]
        conn.close()
        return virus_hashes
    except Exception as e:
        print(f"Error loading virus database: {e}")
        return []

#Hash'in virüs veritabanında olup olmadığını kontrol eder.
def check_virus(hash_value, virus_database):

    return hash_value in virus_database

#Enfekte dosyayı karantina klasörüne taşır.
def quarantine_infected_file(file_path, quarantine_directory):

    try:
        os.makedirs(quarantine_directory, exist_ok=True)
        shutil.move(file_path, quarantine_directory)
        print(f"Infected file moved to quarantine: {file_path}")
    except Exception as e:
        print(f"Error quarantining file {file_path}: {e}")

#Bir dizini tarar, dosyaların hash'lerini çıkarır ve virüs kontrolü yapar.
def scan_directory(directory, virus_database, quarantine_directory, output_file="scan_results.json"):

    results = []
    for file_path in get_all_files(directory):
        print(f"Scanning: {file_path}")
        file_hash = calculate_hash(file_path, 'md5')

        if file_hash:
            is_infected = check_virus(file_hash, virus_database)
            if is_infected:
                quarantine_infected_file(file_path, quarantine_directory)
                results.append({
                    "file_path": file_path,
                    "hash": file_hash,
                    "status": "infected and quarantined"
                })
            else:
                results.append({
                    "file_path": file_path,
                    "hash": file_hash,
                    "status": "clean"
                })
        else:
            results.append({
                "file_path": file_path,
                "hash": None,
                "status": "error"
            })

    # Sonuçları JSON dosyasına yaz
    try:
        with open(output_file, "w", encoding="utf-8") as json_file:
            json.dump(results, json_file, indent=4)
        print(f"Scan results saved to {output_file}")
    except Exception as e:
        print(f"Error writing scan results to JSON: {e}")

    return results

#Temiz dosyayı karantinadan eski konumuna geri taşır.
def restore_clean_file(file_path, original_directory):

    try:
        os.makedirs(original_directory, exist_ok=True)
        shutil.move(file_path, original_directory)
        print(f"Clean file restored to original location: {file_path}")
    except Exception as e:
        print(f"Error restoring file {file_path}: {e}")
