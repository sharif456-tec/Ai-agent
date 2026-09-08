"""Authorized AI Security Agent network scanner module."""

import subprocess


def universal_network_scanner(target, method="nmap", ports="80,443"):
    commands = {
        "nmap": f"nmap -p {ports} -T4 {target}",
        "zmap": f"zmap -p {ports.split(',')[0]} {target} -o-",
        "masscan": f"masscan -p{ports} {target} --rate 1000",
        "whatweb": f"whatweb {target}",
        "nikto": f"nikto -h {target} -Tuning 1,2"
    }

    if method not in commands:
        return {"status": "error", "message": "Invalid method selected."}

    try:
        process = subprocess.Popen(
            commands[method],
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()

        if stderr and b"error" in stderr.lower():
            return {"status": "error", "message": stderr.decode()}

        return {
            "status": "success",
            "method": method,
            "target": target,
            "output": stdout.decode()
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
