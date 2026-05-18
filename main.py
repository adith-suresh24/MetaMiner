#!/usr/bin/env python3
"""
MetaMiner - Extract and analyze file metadata for securityAI.
Supports: PDF, Office (docx/xlsx/pptx), images (jpg/png/tiff), executables (PE),
archives (zip), audio (mp3), video (mp4).
"""

import os
import sys
import json
import hashlib
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Union

# ---- Metadata extraction libraries ----
try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    from docx import Document
except ImportError:
    Document = None

try:
    from openpyxl import load_workbook
except ImportError:
    load_workbook = None

try:
    from pptx import Presentation
except ImportError:
    Presentation = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    Image = None

try:
    import pefile
except ImportError:
    pefile = None

try:
    import magic
except ImportError:
    magic = None

try:
    import exifread
except ImportError:
    exifread = None

try:
    import mutagen
    from mutagen.mp3 import MP3
    from mutagen.mp4 import MP4
    from mutagen.flac import FLAC
except ImportError:
    mutagen = None

# Optional: hachoir for deep metadata (supports many formats)
try:
    from hachoir.parser import createParser
    from hachoir.metadata import extractMetadata
except ImportError:
    createParser = None
    extractMetadata = None


class MetaMiner:
    """Extract and analyze metadata from a given file."""

    # Suspicious patterns for security analysis
    SUSPICIOUS_PDF_KEYWORDS = ["/JavaScript", "/JS", "/Launch", "/OpenAction"]
    SUSPICIOUS_OFFICE_MACROS = ["ThisDocument", "Module", "VBA"]
    SUSPICIOUS_TIMESTAMPS = ["1970-01-01", "1601-01-01"]

    def __init__(self, file_path: Union[str, Path], calculate_hash: bool = True):
        """
        Args:
            file_path: Path to the file to analyze.
            calculate_hash: Whether to compute SHA256 and MD5 hashes.
        """
        self.file_path = Path(file_path)
        self.calculate_hash = calculate_hash

        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        self.mime_type = self._get_mime_type()

    def _get_mime_type(self) -> str:
        """Detect MIME type using python-magic or fallback to extension."""
        if magic:
            try:
                return magic.from_file(str(self.file_path), mime=True)
            except Exception:
                pass
        # Fallback: guess by extension
        ext = self.file_path.suffix.lower()
        mime_map = {
            ".pdf": "application/pdf",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".tiff": "image/tiff",
            ".exe": "application/x-msdownload",
            ".dll": "application/x-msdownload",
            ".zip": "application/zip",
            ".mp3": "audio/mpeg",
            ".mp4": "video/mp4",
        }
        return mime_map.get(ext, "application/octet-stream")

    def extract_all(self) -> Dict[str, Any]:
        """Extract all available metadata and run security analysis."""
        result = {
            "file_path": str(self.file_path),
            "file_size": self.file_path.stat().st_size,
            "mime_type": self.mime_type,
            "hashes": {},
            "metadata": {},
            "security_analysis": {},
        }

        # Hashes
        if self.calculate_hash:
            result["hashes"] = self._compute_hashes()

        # Metadata extraction based on MIME type
        if self.mime_type == "application/pdf":
            result["metadata"] = self._extract_pdf_metadata()
        elif self.mime_type.startswith("application/vnd.openxmlformats"):
            result["metadata"] = self._extract_office_metadata()
        elif self.mime_type.startswith("image/"):
            result["metadata"] = self._extract_image_metadata()
        elif self.mime_type in ("application/x-msdownload", "application/x-dosexec"):
            result["metadata"] = self._extract_pe_metadata()
        elif self.mime_type == "application/zip":
            result["metadata"] = self._extract_zip_metadata()
        elif self.mime_type.startswith("audio/"):
            result["metadata"] = self._extract_audio_metadata()
        elif self.mime_type.startswith("video/"):
            result["metadata"] = self._extract_video_metadata()
        else:
            # Fallback: try hachoir if available
            result["metadata"] = self._extract_hachoir_metadata()

        # Security analysis
        result["security_analysis"] = self._analyze_security(result["metadata"])

        return result

    def _compute_hashes(self) -> Dict[str, str]:
        """Compute SHA256 and MD5 hashes of the file."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(self.file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
                md5.update(chunk)
        return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}

    # ----- PDF Metadata -----
    def _extract_pdf_metadata(self) -> Dict[str, Any]:
        if not PyPDF2:
            return {"error": "PyPDF2 not installed"}
        try:
            with open(self.file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                meta = reader.metadata
                if meta:
                    return {k[1:].lower(): v for k, v in meta.items()}
                return {"page_count": len(reader.pages), "encrypted": reader.is_encrypted}
        except Exception as e:
            return {"error": str(e)}

    # ----- Office Metadata -----
    def _extract_office_metadata(self) -> Dict[str, Any]:
        data = {}
        # Word
        if "wordprocessingml" in self.mime_type and Document:
            try:
                doc = Document(self.file_path)
                core_props = doc.core_properties
                data = {
                    "author": core_props.author,
                    "last_modified_by": core_props.last_modified_by,
                    "created": str(core_props.created),
                    "modified": str(core_props.modified),
                    "revision": core_props.revision,
                }
            except Exception:
                pass
        # Excel
        elif "spreadsheetml" in self.mime_type and load_workbook:
            try:
                wb = load_workbook(self.file_path, read_only=True, data_only=False)
                props = wb.properties
                data = {
                    "creator": props.creator,
                    "last_modified_by": props.lastModifiedBy,
                    "created": str(props.created),
                    "modified": str(props.modified),
                    "title": props.title,
                }
            except Exception:
                pass
        # PowerPoint
        elif "presentationml" in self.mime_type and Presentation:
            try:
                prs = Presentation(self.file_path)
                core_props = prs.core_properties
                data = {
                    "author": core_props.author,
                    "last_modified_by": core_props.last_modified_by,
                    "created": str(core_props.created),
                    "modified": str(core_props.modified),
                }
            except Exception:
                pass
        return data

    # ----- Image Metadata (EXIF, IPTC) -----
    def _extract_image_metadata(self) -> Dict[str, Any]:
        data = {}
        if Image:
            try:
                img = Image.open(self.file_path)
                data["format"] = img.format
                data["mode"] = img.mode
                data["size"] = img.size
                exif = img.getexif()
                if exif:
                    for tag_id, value in exif.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        data[tag_name] = str(value)
            except Exception:
                pass
        if exifread and not data:
            # Alternative exifread
            try:
                with open(self.file_path, "rb") as f:
                    tags = exifread.process_file(f)
                for tag, value in tags.items():
                    data[tag] = str(value)
            except Exception:
                pass
        return data

    # ----- PE (Windows Executable) Metadata -----
    def _extract_pe_metadata(self) -> Dict[str, Any]:
        if not pefile:
            return {"error": "pefile not installed"}
        try:
            pe = pefile.PE(self.file_path)
            data = {}
            # DOS header
            data["e_magic"] = hex(pe.DOS_HEADER.e_magic)
            data["e_lfanew"] = pe.DOS_HEADER.e_lfanew
            # File header
            data["machine"] = hex(pe.FILE_HEADER.Machine)
            data["number_of_sections"] = pe.FILE_HEADER.NumberOfSections
            data["time_date_stamp"] = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat() if pe.FILE_HEADER.TimeDateStamp else None
            # Optional header
            if hasattr(pe, "OPTIONAL_HEADER"):
                data["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
                data["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                data["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
            # Sections
            data["sections"] = [sec.Name.decode().strip("\x00") for sec in pe.sections]
            # Imports
            imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    imports.append(entry.dll.decode())
            data["imported_dlls"] = imports
            pe.close()
            return data
        except Exception as e:
            return {"error": str(e)}

    # ----- ZIP Archive Metadata -----
    def _extract_zip_metadata(self) -> Dict[str, Any]:
        data = {}
        try:
            with zipfile.ZipFile(self.file_path, "r") as zf:
                infos = zf.infolist()
                data["num_files"] = len(infos)
                data["compressed_size"] = sum(f.compress_size for f in infos)
                data["file_names"] = [f.filename for f in infos[:10]]  # first 10
                data["is_encrypted"] = any(f.flag_bits & 0x1 for f in infos)
        except Exception as e:
            data["error"] = str(e)
        return data

    # ----- Audio Metadata -----
    def _extract_audio_metadata(self) -> Dict[str, Any]:
        if not mutagen:
            return {}
        try:
            if self.file_path.suffix.lower() == ".mp3":
                audio = MP3(self.file_path)
            elif self.file_path.suffix.lower() == ".mp4":
                audio = MP4(self.file_path)
            elif self.file_path.suffix.lower() == ".flac":
                audio = FLAC(self.file_path)
            else:
                return {}
            data = {"length_seconds": audio.info.length, "bitrate": audio.info.bitrate}
            # Tags
            for k, v in audio.items():
                data[k] = str(v)
            return data
        except Exception as e:
            return {"error": str(e)}

    # ----- Video Metadata -----
    def _extract_video_metadata(self) -> Dict[str, Any]:
        # Currently same as audio (mutagen also works for mp4 video)
        return self._extract_audio_metadata()

    # ----- Fallback: hachoir parser (very broad support) -----
    def _extract_hachoir_metadata(self) -> Dict[str, Any]:
        if not createParser or not extractMetadata:
            return {"note": "Install hachoir for deep metadata extraction"}
        try:
            parser = createParser(str(self.file_path))
            if not parser:
                return {}
            metadata = extractMetadata(parser)
            if not metadata:
                return {}
            data = {}
            for line in metadata.exportPlaintext():
                if ":" in line:
                    key, val = line.split(":", 1)
                    data[key.strip()] = val.strip()
            parser.stream.close()
            return data
        except Exception as e:
            return {"error": str(e)}

    # ----- Security Analysis -----
    def _analyze_security(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Look for suspicious indicators in extracted metadata."""
        issues = []

        # PDF JavaScript
        if self.mime_type == "application/pdf":
            for kw in self.SUSPICIOUS_PDF_KEYWORDS:
                if any(kw in str(v) for v in metadata.values()):
                    issues.append(f"Contains suspicious PDF keyword: {kw}")

        # Office macros
        if self.mime_type.startswith("application/vnd.openxmlformats"):
            # Quick check: look for vbaProject.bin in zip
            try:
                with zipfile.ZipFile(self.file_path, "r") as zf:
                    for name in zf.namelist():
                        if "vbaProject.bin" in name.lower():
                            issues.append("Contains VBA macros (potential malware)")
                            break
            except Exception:
                pass

        # Suspicious timestamps (e.g., zero dates)
        for key, val in metadata.items():
            if isinstance(val, str) and val.startswith(tuple(self.SUSPICIOUS_TIMESTAMPS)):
                issues.append(f"Suspicious timestamp in {key}: {val}")

        # PE file anomalies
        if self.mime_type in ("application/x-msdownload", "application/x-dosexec"):
            if "entry_point" in metadata:
                ep = metadata["entry_point"]
                if ep and ep.lower() == "0x0":
                    issues.append("Entry point at zero – suspicious")
            if "sections" in metadata and len(metadata["sections"]) > 10:
                issues.append("Unusually many sections (packer?)")

        # Overly recent file? (future date)
        now = datetime.now()
        for key, val in metadata.items():
            if "date" in key.lower() and isinstance(val, str):
                try:
                    dt = datetime.fromisoformat(val.replace("Z", ""))
                    if dt > now:
                        issues.append(f"File timestamp in future: {key} = {val}")
                except Exception:
                    pass

        return {
            "suspicious_indicators": issues,
            "risk_score": len(issues) * 10,  # simple scoring
        }


# ----- Command Line Interface -----
def main():
    import argparse

    parser = argparse.ArgumentParser(description="MetaMiner - Extract and analyze file metadata for securityAI.")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--no-hash", action="store_true", help="Skip hash calculation")
    parser.add_argument("--output", "-o", help="Output JSON file (otherwise print to stdout)")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    args = parser.parse_args()

    try:
        miner = MetaMiner(args.file, calculate_hash=not args.no_hash)
        result = miner.extract_all()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2 if args.pretty else None, default=str)
        print(f"Results written to {args.output}")
    else:
        if args.pretty:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(json.dumps(result, default=str))


if __name__ == "__main__":
    main()