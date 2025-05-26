from pathlib import Path
from dissect.target import Target
from utils.utils import run_target_info, run_target_query

def analyze_image(target_path: Path):
    target = Target.open(target_path)
    hostname = target.hostname
    print(f"Analyzing {target_path} with hostname {hostname}")

    # Run target-info on the target
    system_info = run_target_info(target.path)
    print(f"System Info: {system_info}")

    # Collect information about ssh
    patterns = "ssh"
    ssh_analysis = run_target_query(target, patterns)
    print(f"SSH Analysis: {ssh_analysis}")

    return {
        "path": target_path,
        "hostname": hostname,
    }

def analyze_images_from_directory(directory: str):
    """
    Analyze all forensic images in a directory.
    """
    results = []

    for target_path in Path(directory).glob("*.qcow2"):
        result = analyze_image(target_path)
        results.append(result)

    return results

if __name__ == "__main__":
    targets_directory = "./targets"
    analysis_results = analyze_images_from_directory(targets_directory)
    print(analysis_results)
