"""Build vector index from official MITRE ATT&CK STIX data and OWASP Top 10."""

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from openai import OpenAI

from app.config import get_settings
from app.rag import COLLECTION_NAME, TechniqueCandidate

# ── Pinned upstream sources ──────────────────────────────────────────────────
MITRE_VERSION = "v16.1"
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"{MITRE_VERSION}/enterprise-attack/enterprise-attack.json"
)

OWASP_COMMIT = "3a31f35346c3f4e90f350395124382fa53af2afe"
OWASP_BASE_URL = (
    f"https://raw.githubusercontent.com/OWASP/Top10/{OWASP_COMMIT}/2021/docs/en"
)

OWASP_FILES = [
    "A01_2021-Broken_Access_Control.md",
    "A02_2021-Cryptographic_Failures.md",
    "A03_2021-Injection.md",
    "A04_2021-Insecure_Design.md",
    "A05_2021-Security_Misconfiguration.md",
    "A06_2021-Vulnerable_and_Outdated_Components.md",
    "A07_2021-Identification_and_Authentication_Failures.md",
    "A08_2021-Software_and_Data_Integrity_Failures.md",
    "A09_2021-Security_Logging_and_Monitoring_Failures.md",
    "A10_2021-Server-Side_Request_Forgery_(SSRF).md",
]


# ── Parsing functions ────────────────────────────────────────────────────────


def parse_mitre_stix(stix_data: dict[str, Any]) -> list[TechniqueCandidate]:
    """Parse MITRE ATT&CK STIX JSON into one candidate per technique/sub-technique.

    Skips revoked and deprecated techniques.
    """
    candidates: list[TechniqueCandidate] = []
    objects = stix_data.get("objects", [])

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        # Skip revoked or deprecated entries
        if obj.get("revoked") is True:
            continue
        if obj.get("x_mitre_deprecated") is True:
            continue

        # Find external ID (e.g. T1078 or T1078.001)
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break

        if not tech_id:
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")
        detection = obj.get("x_mitre_detection", "")

        tactics: list[str] = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name")
                if phase_name and phase_name not in tactics:
                    tactics.append(phase_name)

        candidates.append(
            TechniqueCandidate(
                technique_id=tech_id,
                name=name,
                framework="MITRE ATT&CK",
                tactics=tactics,
                description=description,
                detection=detection,
            )
        )

    return candidates


def parse_owasp_markdown(filename: str, content: str) -> TechniqueCandidate:
    """Parse an OWASP Top 10 markdown document into a single TechniqueCandidate."""
    # Match ID pattern like A01:2021 or A01_2021
    id_match = re.search(r"A\d{2}[_:]\d{4}", filename)
    cat_id = id_match.group(0).replace("_", ":") if id_match else filename

    # Extract title from markdown H1
    h1_pattern = r"^#\s+(?:A\d{2}:\d{4}\s*[-\u2013\u2014]\s*)?([^\n\r]+)"
    title_match = re.search(h1_pattern, content, re.MULTILINE)
    name = title_match.group(1).strip() if title_match else filename

    # Extract overview/description
    # Strip markdown headers and collapse
    lines = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    description = " ".join(lines[:10])  # First few paragraphs as description

    return TechniqueCandidate(
        technique_id=cat_id,
        name=name,
        framework="OWASP Top 10",
        tactics=["web-application-security"],
        description=description,
        detection="",
    )


def format_document_for_embedding(candidate: TechniqueCandidate) -> str:
    """Format a candidate document for semantic vector embedding."""
    parts = [
        f"Framework: {candidate.framework}",
        f"Technique ID: {candidate.technique_id}",
        f"Name: {candidate.name}",
    ]
    if candidate.tactics:
        parts.append(f"Tactics: {', '.join(candidate.tactics)}")
    if candidate.description:
        parts.append(f"Description: {candidate.description}")
    if candidate.detection:
        parts.append(f"Detection: {candidate.detection}")
    return "\n".join(parts)


# ── Download & Persistence helpers ───────────────────────────────────────────


def download_mitre_stix(data_dir: Path) -> Path:
    """Download MITRE ATT&CK STIX JSON and save to data/raw/mitre/."""
    mitre_dir = data_dir / "raw" / "mitre"
    mitre_dir.mkdir(parents=True, exist_ok=True)
    target_file = mitre_dir / "enterprise-attack.json"
    metadata_file = mitre_dir / "metadata.json"

    if not target_file.exists():
        print(f"Downloading MITRE ATT&CK {MITRE_VERSION} from {MITRE_URL}...")
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            resp = client.get(MITRE_URL)
            resp.raise_for_status()
            target_file.write_bytes(resp.content)

        metadata = {
            "source": "mitre-attack/attack-stix-data",
            "url": MITRE_URL,
            "version": MITRE_VERSION,
            "downloaded_at": datetime.now(UTC).isoformat(),
        }
        metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return target_file


def download_owasp_docs(data_dir: Path) -> list[Path]:
    """Download OWASP Top 10 2021 markdown docs to data/raw/owasp/."""
    owasp_dir = data_dir / "raw" / "owasp"
    owasp_dir.mkdir(parents=True, exist_ok=True)
    metadata_file = owasp_dir / "metadata.json"

    downloaded: list[Path] = []
    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        for fname in OWASP_FILES:
            file_path = owasp_dir / fname
            if not file_path.exists():
                url = f"{OWASP_BASE_URL}/{fname}"
                print(f"Downloading {fname} from {url}...")
                resp = client.get(url)
                resp.raise_for_status()
                file_path.write_text(resp.text, encoding="utf-8")
            downloaded.append(file_path)

    if not metadata_file.exists():
        metadata = {
            "source": "OWASP/Top10",
            "base_url": OWASP_BASE_URL,
            "commit": OWASP_COMMIT,
            "version": "2021",
            "downloaded_at": datetime.now(UTC).isoformat(),
            "files": OWASP_FILES,
        }
        metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return downloaded


def build_index(data_dir: Path, dry_run: bool = False) -> int:
    """Download sources, parse technique documents, and index into Chroma."""
    import chromadb

    settings = get_settings()

    # 1. Download
    mitre_file = download_mitre_stix(data_dir)
    owasp_files = download_owasp_docs(data_dir)

    # 2. Parse MITRE
    with mitre_file.open("r", encoding="utf-8") as f:
        stix_data = json.load(f)
    mitre_candidates = parse_mitre_stix(stix_data)
    print(f"Parsed {len(mitre_candidates)} MITRE ATT&CK techniques/sub-techniques.")

    # 3. Parse OWASP
    owasp_candidates: list[TechniqueCandidate] = []
    for owasp_file in owasp_files:
        content = owasp_file.read_text(encoding="utf-8")
        owasp_candidates.append(parse_owasp_markdown(owasp_file.name, content))
    print(f"Parsed {len(owasp_candidates)} OWASP Top 10 categories.")

    all_candidates = mitre_candidates + owasp_candidates
    print(f"Total documents to index: {len(all_candidates)}")

    if dry_run:
        print("Dry run requested; skipping embedding and Chroma storage.")
        return len(all_candidates)

    # 4. Embed & Index into Chroma
    client = chromadb.PersistentClient(path=settings.chroma_persist_dir)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    openai_client = OpenAI(api_key=settings.openai_api_key)
    batch_size = 100

    for i in range(0, len(all_candidates), batch_size):
        batch = all_candidates[i : i + batch_size]
        docs = [format_document_for_embedding(c) for c in batch]
        ids = [c.technique_id for c in batch]
        metadatas = [
            {
                "name": c.name,
                "framework": c.framework,
                "tactics": ", ".join(c.tactics),
                "description": c.description[:500],
                "detection": c.detection[:500],
            }
            for c in batch
        ]

        # Generate embeddings
        res = openai_client.embeddings.create(
            input=docs,
            model=settings.embedding_model,
        )
        embeddings = [item.embedding for item in res.data]

        collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=docs,
            metadatas=metadatas,
        )
        current_batch = i // batch_size + 1
        total_batches = (len(all_candidates) - 1) // batch_size + 1
        print(f"Indexed batch {current_batch}/{total_batches}")

    print("Indexing completed successfully.")
    return len(all_candidates)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build SentinelAI vector index.")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data"),
        help="Directory to store raw knowledge data.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Download and parse without calling embedding API or saving to Chroma.",
    )
    args = parser.parse_args()
    build_index(data_dir=args.data_dir, dry_run=args.dry_run)
