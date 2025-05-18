import datetime
import json
from pathlib import Path
import subprocess
from dissect.target import Target
from dissect.target.plugin import find_functions

from models.system_info import SystemInfo, parse_system_info

def create_target_info_command(target_path: Path) -> list[str]:
    command = [
        "target-info",
        "-q",
        str(target_path),
        "--json",
    ]
    return command

def create_target_query_command(target_path: Path, function_names: list[str]) -> list[str]:
    command = [
        "target-query",
        "-q",
        str(target_path),
        "-f", ",".join(function_names),
    ]
    return command

def run_target_info(target_path: str) -> SystemInfo:
    command_info = create_target_info_command(target_path)
    result = subprocess.run(command_info, capture_output=True, check=True, text=True)

    system_info = parse_system_info(json.loads(result.stdout))

    return system_info

def run_target_query(target: Target, patterns: str):
    functions, _ = find_functions(patterns, target, compatibility=False, show_hidden=True)
    function_names = sorted({func.name for func in functions})

    command = create_target_query_command(target.path, function_names)
    result = subprocess.run(command, capture_output=True, check=True, text=True)
    print(result.stdout)
    return result.stdout

def analyze_image(target_path: Path, output_dir: Path = Path("outputs")):
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

    # bash history/commands
    # crontabs
    # network activity
    # filesystem


    # TODO Find dissect functions suitable for the image analysis:
    # General functions such as os, architecture, version, hostname, domain
    # User accounts, login history
    # Crontab
    # Network connections, open ports
    # SSH configs keys, known_hosts, unusual configs
    # Filesystem - searching for suspicious files (recently modified, setuid files, hidden files)

    # # Ensure output directory exists
    # output_dir.mkdir(parents=True, exist_ok=True)

    # # Create output file with timestamp
    # timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
    # output_filename = f"{target_path.stem}_{timestamp}.out"
    # output_path = output_dir / output_filename

    # try:
    #     with open(output_path, "w") as outfile:
    #         subprocess.run(command, stdout=outfile, stderr=subprocess.PIPE, check=True)
    #     print(f"Output written to {output_path}")
    # except subprocess.CalledProcessError as e:
    #     print(f"[ERROR] target-query failed: {e.stderr.decode()}")
    #     return None

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

# Example usage
if __name__ == "__main__":
    targets_directory = "./targets"
    analysis_results = analyze_images_from_directory(targets_directory)
