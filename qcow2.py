import os
import subprocess

class QCOW2Helper:
    @staticmethod
    def create_standalone_image(snapshot_image_path: str) -> str:
        if not os.path.isfile(snapshot_image_path):
            raise FileNotFoundError(f"Snapshot image '{snapshot_image_path}' does not exist.")

        standalone_image_path = os.path.basename(snapshot_image_path).replace(".qcow2", "_standalone.qcow2")
        standalone_image_path = os.path.join(os.path.dirname(snapshot_image_path), standalone_image_path)
        try:
            # qemu-img rebase -b baseline_targets/ubuntu-22.04-packer.qcow2 -F qcow2 snapshots/snapshot-ubuntu_2204.qcow2
            # qemu-img commit snapshots/snapshot-ubuntu_2204.qcow2
            # qemu-img convert -O qcow2 snapshots/snapshot-ubuntu_2204.qcow2 snapshots/snapshot-ubuntu_2204.qcow2

            # qemu-img convert -O qcow2 snapshots/snapshot-ubuntu_2204.qcow2 snapshots/snapshot-ubuntu_2204_standalone.qcow2
            subprocess.run(
                ["qemu-img", "convert", "-O", "qcow2", snapshot_image_path, standalone_image_path],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT
            )
            print(f"Standalone qcow2 image created successfully: {standalone_image_path}")
            return standalone_image_path
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to create standalone image: {e}")

    @staticmethod
    def cleanup(standalone_image_path: str):
        if os.path.exists(standalone_image_path):
            os.remove(standalone_image_path)
            print(f"Removed temporary standalone image: {standalone_image_path}")
        else:
            print("No temporary standalone image to remove.")
