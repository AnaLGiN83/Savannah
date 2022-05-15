import os
import subprocess


def tail(path, line_count):
    try:
        return 0, subprocess.check_output(f"tail -n{line_count} {path}")
    except subprocess.CalledProcessError as ex:
        return ex.returncode, None


def tail_jq(path, line_count, jq_command):
    try:
        return 0, subprocess.check_output(f"tail -n{line_count} {path} | jq -c '{jq_command}'", shell=True).decode('ascii').split('\n')
    except subprocess.CalledProcessError as ex:
        return ex.returncode, None


def ctl_status(service_name):
    try:
        return 0, subprocess.check_output(f"systemctl status {service_name} | grep Active", shell=True).decode('ascii')[13:]
    except subprocess.CalledProcessError as ex:
        return ex.returncode, None
