import argparse
import logging
import json
from pathlib import Path
from datetime import datetime
from analyze_snapshots import analyze_image
from qcow2 import QCOW2Helper
from virus_total import VirusTotalClient

logging.basicConfig(
    level=logging.INFO,  # Change to DEBUG for more detailed output
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),  # Log to console
        logging.FileHandler("pipeline.log"),  # Log to a file
    ]
)

logger = logging.getLogger(__name__)

OUTPUT_DIRECTORY = "./pipeline_output"

def filter_snapshots(directory: Path, min_size: int, start_date: datetime, end_date: datetime):
    """
    Filter snapshots that are larger than `min_size` and have a modified time within `start_date` and `end_date`.
    """
    if not directory.exists():
        return []

    valid_snapshots = []
    for file_path in directory.rglob("snapshot-*"):
        if not file_path.is_file():
            continue

        size = file_path.stat().st_size
        mtime = datetime.fromtimestamp(file_path.stat().st_mtime)

        if size >= min_size and start_date <= mtime <= end_date:
            valid_snapshots.append((file_path, mtime))

    valid_snapshots.sort(key=lambda x: x[1], reverse=True)

    return valid_snapshots

def query_malware_database(hash_value: str):
    client = VirusTotalClient()
    try:
        file_obj = client.check_hash(hash_value)
    except Exception:
        client.close()
        return None

    result = {
        "self_link": f"https://www.virustotal.com/gui/file/{hash_value}",
        "sha256": str(file_obj.sha256),
        "first_submission_date": str(file_obj.first_submission_date),
        "last_analysis_date": str(file_obj.last_analysis_date),
        "reputation": file_obj.reputation,
        "total_votes": dict(file_obj.total_votes),
        "last_analysis_stats": dict(file_obj.last_analysis_stats),
        **({"popular_threat_classification": dict(file_obj.popular_threat_classification)}
           if getattr(file_obj, "popular_threat_classification", None) else {}),
    }
    client.close()
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filter snapshot files by size and date.")
    parser.add_argument("directory", type=str, help="Path to the target snapshots directory.")
    args = parser.parse_args()

    path = Path(args.directory)
    if not path.exists():
        logger.info(f"Directory {path} does not exist.")
        exit(1)

    min_size = 100 * 1024 * 1024  # Minimum size of 100 MB
    start_date = datetime(2025, 5, 1)  # Start date
    end_date = datetime(2025, 5, 30)  # End date
    snapshots = filter_snapshots(path, min_size, start_date, end_date)

    for s in snapshots:
        output_file = Path(OUTPUT_DIRECTORY) / f"{s[0].stem}_analysis.json"
        if output_file.exists():
            logger.info(f"Analysis for {s[0]} already exists. Skipping...")
            continue

        logger.info(f"File: {s[0]}, Last Modified: {s[1]}")

        # Convert to a QCOW2 standalone
        logger.info(f"Creating standalone image for: {s[0]}")
        standalone_path = QCOW2Helper.create_standalone_image(s[0])
        logger.info("Standalone image created.")

        # Analyze the snapshot
        logger.info(f"Analyzing snapshot: {s[0]}")
        indicators = analyze_image(standalone_path)
        logger.info(f"Number of found files: {len(indicators.get('files', []))}")

        output_file = Path(OUTPUT_DIRECTORY) / f"{s[0].stem}_analysis.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with output_file.open("w") as f:
            json.dump(indicators, f, indent=2)

        logger.info(f"Analysis completed for {s[0]}")

        # Cleanup the standalone image
        QCOW2Helper.cleanup(standalone_path)
        logger.info(f"Temporary standalone image {standalone_path} removed.")

        # Deduplicate the analysis results based on sha256 hash
        seen = set()
        unique_files = [
            f for f in indicators.get("files", [])
            if (lambda h: not (h in seen or seen.add(h)))(f.get("sha256"))
        ]
        indicators["files"] = unique_files
        logger.info(f"Number of files after deduplication: {len(unique_files)}")

        output_file = Path(OUTPUT_DIRECTORY) / f"unique_{s[0].stem}_analysis.json"
        with output_file.open("w") as f:
            json.dump(indicators, f, indent=2)

        # Query malware database
        reports = []
        for file in indicators.get("files", []):
            if "sha256" in file:
                logger.info(f"Querying malware database for SHA256: {file['sha256']}")
                vt_result = query_malware_database(file["sha256"])
                if vt_result:
                    logger.info(f"Found VT report for {file['sha256']}")
                    reports.append(vt_result)

        if reports != []:
            output_file = Path(OUTPUT_DIRECTORY) / f"mal_db_{s[0].stem}_analysis.json"
            with output_file.open("w") as f:
                json.dump(reports, f, indent=2)

        logger.info("=========================================================")
