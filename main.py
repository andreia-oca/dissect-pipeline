import datetime
from pathlib import Path
import subprocess
from dissect.target import Target
from dissect.target.plugin import find_functions

def create_target_query_command(target_path: Path, function_names: list[str]) -> list[str]:
    command = [
        "target-query",
        str(target_path),
        "-f", ",".join(function_names),
        "-q"
    ]
    return command

def analyze_image(target_path: Path, output_dir: Path = Path("outputs"), dry_run: bool = False):
    target = Target.open(target_path)
    hostname = target.hostname
    print(f"Analyzing {target_path} with hostname {hostname}")

    # TODO Find dissect functions suitable for the image analysis:
    # General functions such as os, architecture, version, hostname, domain
    # User accounts, login history
    # Crontab
    # Network connections, open ports
    # SSH configs keys, known_hosts, unusual configs
    # Filesystem - searching for suspicious files (recently modified, setuid files, hidden files)
    patterns = "os,architecture,version,hostname,domain"

    functions, _ = find_functions(patterns, target, compatibility=False, show_hidden=True)
    print(f"Raw function descriptors: {functions}")

    function_names = sorted({func.name for func in functions})
    print(f"Found {len(function_names)} functions for {target_path}.")
    print(f"Functions: {function_names}")

    # Apply the functions to the image
    command = create_target_query_command(target_path, function_names)
    print(f"Running: {" ".join(command)}")


    if not dry_run:
        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create output file with timestamp
        timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
        output_filename = f"{target_path.stem}_{timestamp}.out"
        output_path = output_dir / output_filename

        try:
            with open(output_path, "w") as outfile:
                subprocess.run(command, stdout=outfile, stderr=subprocess.PIPE, check=True)
            print(f"Output written to {output_path}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] target-query failed: {e.stderr.decode()}")
            return None

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
        result = analyze_image(target_path, dry_run=True)
        results.append(result)

    return results

# Example usage
if __name__ == "__main__":
    targets_directory = "./targets"
    analysis_results = analyze_images_from_directory(targets_directory)
