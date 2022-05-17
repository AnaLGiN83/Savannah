import os
import subprocess


def tail(path, line_count):
    try:
        return 0, subprocess.check_output(f"tail -n{line_count} {path}").decode('ascii')
    except subprocess.CalledProcessError as ex:
        return ex.returncode, None
    except FileNotFoundError:
        return -1, None


def ctl_status(service_name):
    try:
        return 0, subprocess.check_output(f"systemctl status {service_name} | grep Active", shell=True).decode('ascii')[13:]
    except subprocess.CalledProcessError as ex:
        return ex.returncode, None
    except FileNotFoundError:
        return -1, None


def suricata_update():
    try:
        return 0, subprocess.check_output(f"suricata-update").decode('ascii')
    except subprocess.CalledProcessError as ex:
        return ex.returncode, None
    except FileNotFoundError:
        return -1, None
