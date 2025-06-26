import json
import re
from pathlib import Path
from dissect.target import Target

TIMESTAMP_REGEX = r"-(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)$"
PATHS = [
    "/var/log/ffiles/",
]

def analyze_image(target_path: Path):
    target = Target.open(target_path)
    hostname = target.hostname
    os = target.os
    install_date = target.install_date
    activity = target.activity

    paths = PATHS

    files = [
        {
            "path": entry.path,
            "md5": entry.md5(),
            "sha1": entry.sha1(),
            "sha256": entry.sha256(),
            "size": entry.stat().st_size,
            "filename": entry.name,
            "realpath": str(Path(entry.path).relative_to(scan_path).parent / re.sub(TIMESTAMP_REGEX, '', entry.name)) if entry.path.startswith(scan_path) else entry.path,
            "realmtime": re.search(TIMESTAMP_REGEX, entry.name).group(1) if re.search(TIMESTAMP_REGEX, entry.name) else None,
        }
        for fs in target.filesystems
        for scan_path in paths
        for _, _, filenames in fs.walk_ext(scan_path)
        for entry in filenames
    ]

    return {
        "target_path": str(target_path),
        "hostname": str(hostname),
        "os": str(os),
        "install_date": str(install_date),
        "last_activity": str(activity),
        "files": files,
    }

def analyze_images_from_directory(directory: str, output_directory: str = "./output"):
    """
    Analyze all forensic images in a directory.
    """
    results = []

    for target_path in Path(directory).glob("*.qcow2"):
        result = analyze_image(target_path)

        # Write the results to a json file
        output_file = Path(output_directory) / f"{target_path.stem}_analysis.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with output_file.open("w") as f:
            json.dump(result, f, indent=2)

        results.append(result)

    return results

if __name__ == "__main__":
    targets_directory = "./targets"
    analysis_results = analyze_images_from_directory(targets_directory)
