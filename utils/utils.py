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