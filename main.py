from pathlib import Path
from dissect.target import Target

def analyze_image(target_path: Path):
    target = Target.open(target_path)
    hostname = target.hostname

    # TODO Find functions suitable for the image analysis

    # TODO Apply the functions to the image

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

    print(analysis_results)
