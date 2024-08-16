import os
import subprocess

# Handles the process of running a command and capturing stdout, stderr, and the return code.
# This function serves as a helper to allow arbitrary commands to be ran in python and the
# output of that command processed.
def performCommandLineOperation( command ):

    proc = subprocess.Popen(command,
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()

    return proc.returncode, stdout, stderr
