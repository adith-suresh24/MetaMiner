import os
import sys
import json
import csv
import hashlib
import argparse
import mimetypes
import struct
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

# ------------------------------
# EXTERNAL LIBRARIES
# ------------------------------
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    Image = None

try:
    import docx
except ImportError:
    docx = None

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    from mutagen import File as MutagenFile
except ImportError:
    MutagenFile = None

# ------------------------------
# CORE UTILITIES
# ------------------------------

class HashingEngine:
    @staticmethod
    def generate_hashes(file_path: str) -> Dict[str, str]:
        """Generates MD5, SHA1, and SHA256 hashes for a file."""
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            return {
                "MD5": md5_hash.hexdigest(),
                "SHA1": sha1_hash.hexdigest(),
                "SHA256": sha256_hash.hexdigest()
            }
        except Exception as e:
            return {"Error": str(e)}

class FileAnalyzer:
    @staticmethod
    def get_file_stats(file_path: str) -> Dict[str, Any]:
        """Retrieves basic OS-level file statistics."""
        try:
            stats = os.stat(file_path)
            return {
                "size": stats.st_size,
                "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stats.st_atime).isoformat()
            }
        except Exception as e:
            return {"Error": str(e)}

    @staticmethod
    def detect_type(file_path: str) -> Dict[str, str]:
        """Detects MIME type and extension."""
        mime_type, encoding = mimetypes.guess_type(file_path)
        
        # Fallback for files without extensions or unknown types
        if not mime_type:
            try:
                # Simple signature check (magic bytes)
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                    if header.startswith(b'\x89PNG'):
                        mime_type = "image/png"
                    elif header.startswith(b'\xff\xd8\xff'):
                        mime_type = "image/jpeg"
                    elif header.startswith(b'PK\x03\x04'):
                        mime_type = "application/zip" # Could also be docx/xlsx
                    else:
                        mime_type = "application/octet-stream"
            except:
                mime_type = "unknown"

        return {
            "mime_type": mime_type,
            "encoding": encoding,
            "extension": Path(file_path).suffix
        }

# ------------------------------
# EXTRACTORS
# ------------------------------

class ImageExtractor:
    @staticmethod
    def extract(file_path: str) -> Dict:
        data = {"format": "Unknown", "meta": {}}
        if not Image:
            return data
        
        try:
            img = Image.open(file_path)
            data["format"] = img.format
            data["meta"]["resolution"] = img.size
            data["meta"]["mode"] = img.mode
            
            # EXIF Data
            exif_data = img._getexif()
            if exif_data:
                for tag, value in exif_data.items():
                    tag_name = TAGS.get(tag, tag)
                    if tag_name == "GPSInfo":
                        gps_data = {}
                        for t in value:
                            gps_tag = GPSTAGS.get(t, t)
                            gps_data[gps_tag] = value[t]
                        data["meta"]["gps"] = gps_data
                    else:
                        data["meta"][tag_name] = str(value)
        except Exception as e:
            data["Error"] = str(e)
        return data

class DocxExtractor:
    @staticmethod
    def extract(file_path: str) -> Dict:
        data = {"meta": {}}
        if not docx:
            return data
        
        try:
            d = docx.Document(file_path)
            core_props = d.core_properties
            data["meta"]["author"] = core_props.author
            data["meta"]["last_modified_by"] = core_props.last_modified_by
            data["meta"]["created"] = str(core_props.created)
            data["meta"]["modified"] = str(core_props.modified)
            data["meta"]["title"] = core_props.title
            data["meta"]["application"] = core_props.application
        except Exception as e:
            data["Error"] = str(e)
        return data

class PdfExtractor:
    @staticmethod
    def extract(file_path: str) -> Dict:
        data = {"meta": {}}
        if not PyPDF2:
            return data
            
        try:
            with open(file_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                meta = reader.metadata
                if meta:
                    data["meta"]["author"] = meta.get('/Author')
                    data["meta"]["creator"] = meta.get('/Creator')
                    data["meta"]["producer"] = meta.get('/Producer')
                    data["meta"]["creation_date"] = str(meta.get('/CreationDate'))
                    data["meta"]["mod_date"] = str(meta.get('/ModDate'))
                data["meta"]["pages"] = len(reader.pages)
        except Exception as e:
            data["Error"] = str(e)
        return data

class MediaExtractor:
    @staticmethod
    def extract(file_path: str) -> Dict:
        data = {"meta": {}}
        if not MutagenFile:
            return data
            
        try:
            audio = MutagenFile(file_path)
            if audio:
                # Common tags
                tags = audio.tags if audio.tags else {}
                data["meta"]["format"] = audio.info.pprint() if hasattr(audio.info, 'pprint') else str(type(audio.info))
                data["meta"]["length"] = str(audio.info.length) + " seconds"
                
                if tags:
                    data["meta"]["artist"] = tags.get("artist", ["N/A"])[0]
                    data["meta"]["title"] = tags.get("title", ["N/A"])[0]
                    data["meta"]["date"] = tags.get("date", ["N/A"])[0]
        except Exception as e:
            data["Error"] = str(e)
        return data

# ------------------------------
# MAIN ENGINE
# ------------------------------

class MetadataEngine:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.report = {}

    def analyze(self) -> Dict[str, Any]:
        # 1. Basic File Info
        self.report["file_name"] = Path(self.file_path).name
        self.report["file_stats"] = FileAnalyzer.get_file_stats(self.file_path)
        self.report["file_type"] = FileAnalyzer.detect_type(self.file_path)
        
        # 2. Hashes
        self.report["hashes"] = HashingEngine.generate_hashes(self.file_path)
        
        # 3. Specific Metadata
        self.report["metadata"] = {}
        f_type = self.report["file_type"]["mime_type"]
        
        if "image" in f_type:
            self.report["metadata"] = ImageExtractor.extract(self.file_path)
        elif "pdf" in f_type:
            self.report["metadata"] = PdfExtractor.extract(self.file_path)
        elif "wordprocessingml" in f_type or "docx" in f_type: # crude check
            self.report["metadata"] = DocxExtractor.extract(self.file_path)
        elif "audio" in f_type or "video" in f_type:
            self.report["metadata"] = MediaExtractor.extract(self.file_path)

        # 4. Indicators (Heuristics)
        self.report["indicators"] = self._check_indicators()
        
        return self.report

    def _check_indicators(self) -> List[str]:
        ind = []
        # Check GPS
        meta = self.report.get("metadata", {})
        if meta.get("meta", {}).get("gps"):
            ind.append("GPS Data Present")
        
        stats = self.report.get("file_stats", {})
        mod = datetime.fromisoformat(stats.get("modified"))
        create = datetime.fromisoformat(stats.get("created"))
        
        # Suspicious: Modified before created (logic might vary by OS)
        if mod < create:
            ind.append("Timestamp Anomaly (Mod < Create)")
            
        return ind

# ------------------------------
# USER INTERFACE (CLI)
# ------------------------------

def print_report_json(report):
    print(json.dumps(report, indent=4))

def print_report_text(report):
    print("="*40)
    print(f"FILE METADATA REPORT: {report.get('file_name')}")
    print("="*40)
    
    print("\n--- FILE IDENTIFICATION ---")
    print(f"Type: {report['file_type'].get('mime_type')}")
    print(f"Extension: {report['file_type'].get('extension')}")
    
    print("\n--- TIMESTAMPS ---")
    print(f"Created: {report['file_stats'].get('created')}")
    print(f"Modified: {report['file_stats'].get('modified')}")
    print(f"Accessed: {report['file_stats'].get('accessed')}")
    
    print("\n--- HASHES ---")
    for h, val in report['hashes'].items():
        print(f"{h}: {val}")
        
    print("\n--- EMBEDDED METADATA ---")
    meta = report.get('metadata', {}).get('meta', {})
    if not meta:
        print("No specific metadata found.")
    else:
        for k, v in meta.items():
            print(f"{k}: {v}")
            
    print("\n--- SECURITY INDICATORS ---")
    ind = report.get('indicators', [])
    if not ind:
        print("None detected.")
    else:
        for i in ind:
            print(f"[!] {i}")

def save_csv(reports, filename="metadata_report.csv"):
    if not reports: return
    keys = reports[0