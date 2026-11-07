import os
import subprocess

processes = []
for mode, port in (("admin", 8080), ("subscription", 8081)):
    environment = os.environ.copy()
    environment["SERVER_MODE"] = mode
    processes.append(subprocess.Popen([
        "gunicorn",
        "--bind", f"0.0.0.0:{port}",
        "--workers", "1",
        "app:app",
    ], env=environment))

try:
    for process in processes:
        process.wait()
finally:
    for process in processes:
        process.terminate()
