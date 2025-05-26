from dissect.target import Target
from dissect.target.containers.qcow2 import QCow2Container
from pathlib import Path
from dissect.hypervisor.disk.qcow2 import QCow2


def analyze_image(target_path: Path, backing_path: Path):
    target = Target.open(backing_path)

    with target_path.open("rb") as snap_fh, backing_path.open("rb") as base_fh:
        container = QCow2Container(snap_fh, None, backing_file=base_fh)
        disk = QCow2(container)
        target.disks.add(disk)
        target.apply()

        users = target.users()

        print(f"{target_path} / {backing_path}")
        print("Hostname:", target.hostname)
        print("OS:", target.os)
        print("Install date:", target.install_date)
        print("Last activity:", target.activity)
        print("Users:", [user.name for user in users])

    return {
        "path": target_path,
    }

def analyze_images_from_directory(directory: str):
    """
    Analyze all forensic images in a directory.
    """
    backing_path = Path("./snapshots/ubuntu-22.04-packer.qcow2")
    results = []

    for target_path in Path(directory).glob("*.qcow2"):
        analysis = analyze_image(target_path, backing_path)
        results.append(analysis)

    return results

if __name__ == "__main__":
    targets_directory = "./snapshots"
    result = analyze_images_from_directory(targets_directory)
