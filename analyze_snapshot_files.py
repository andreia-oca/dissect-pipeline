import json
from pathlib import Path
from dissect.target import Target

PATHS = [
    "/tmp",
    "/var/log/ffiles",
]

def analyze_image(target_path: Path):
    target = Target.open(target_path)
    hostname = target.hostname
    os = target.os
    install_date = target.install_date
    activity = target.activity

    # TODO: Dump files to be able to compute hashes
    # TODO: Compute hashes for files

    files = [
        {
            "path": str(record.path),
        }
        for path in PATHS
        for record in target.walkfs(path)
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
    # print(json.dumps(analysis_results, indent=2))
