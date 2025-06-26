import json
from pathlib import Path
from datetime import datetime
from analyze_snapshots import analyze_image
from qcow2 import QCOW2Helper
from virus_total import VirusTotalClient

OUTPUT_DIRECTORY = "./pipeline_output"
TARGETS_DIRECTORY = "./snapshots"
SNAPSHOT_NO = 5

def map_files_to_mtime(directory: Path):
    """
    Map files to their last modified time.
    """
    if not directory.exists():
        return None

    file_mtime_map = {}
    for file_path in directory.rglob("snapshot-*"):
        if file_path.is_file():
            mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
            file_mtime_map[file_path] = mtime

    # Sort the dictionary by mtime in descending order
    file_mtime_map = sorted(file_mtime_map.items(), key=lambda item: item[1], reverse=True)

    return file_mtime_map

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
    path = Path(TARGETS_DIRECTORY)
    snapshots = map_files_to_mtime(path)[:SNAPSHOT_NO]

    for s in snapshots:
        output_file = Path(OUTPUT_DIRECTORY) / f"{s[0].stem}_analysis.json"
        if output_file.exists():
            print(f"Analysis for {s[0]} already exists. Skipping...")
            continue

        print(f"File: {s[0]}, Last Modified: {s[1]}")

        # Convert to a QCOW2 standalone
        print(f"Creating standalone image for: {s[0]}")
        standalone_path = QCOW2Helper.create_standalone_image(s[0])
        print("Standalone image created.")

        # Analyze the snapshot
        print(f"Analyzing snapshot: {s[0]}")
        indicators = analyze_image(standalone_path)
        print(f"Length of files: {len(indicators.get('files', []))}")

        output_file = Path(OUTPUT_DIRECTORY) / f"{s[0].stem}_analysis.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with output_file.open("w") as f:
            json.dump(indicators, f, indent=2)

        print(f"Analysis completed for {s[0]}")

        # Cleanup the standalone image
        QCOW2Helper.cleanup(standalone_path)
        print(f"Temporary standalone image {standalone_path} removed.")

        # Deduplicate the analysis results based on sha256 hash
        seen = set()
        unique_files = [
            f for f in indicators.get("files", [])
            if (lambda h: not (h in seen or seen.add(h)))(f.get("sha256"))
        ]
        indicators["files"] = unique_files
        print(f"Length of files after deduplication: {len(unique_files)}")

        output_file = Path(OUTPUT_DIRECTORY) / f"unique_{s[0].stem}_analysis.json"
        with output_file.open("w") as f:
            json.dump(indicators, f, indent=2)

        # Query malware database
        reports = []
        for file in indicators.get("files", []):
            if "sha256" in file:
                print(f"Querying malware database for SHA256: {file['sha256']}")
                vt_result = query_malware_database(file["sha256"])
                if vt_result:
                    reports.append(vt_result)

        if reports != []:
            output_file = Path(OUTPUT_DIRECTORY) / f"mal_db_{s[0].stem}_analysis.json"
            with output_file.open("w") as f:
                json.dump(reports, f, indent=2)

        print("=========================================================")
