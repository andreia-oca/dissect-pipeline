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

    users = target.users()
    home_paths: list[str] = [
        str(user.home) for user in users if user.uid > 1000 and user.name != "nobody" and user.home is not None
    ]
    paths = PATHS + home_paths

    files = [
        {
            "path": entry.path,
            "md5": entry.md5(),
            "sha1": entry.sha1(),
            "sha256": entry.sha256(),
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
