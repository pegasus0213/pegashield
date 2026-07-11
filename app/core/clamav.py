import os
import re
import subprocess

from PySide6.QtCore import QThread, Signal

from app.core.paths import DATABASE_DIRECTORY


# =================================================
# Common ClamAV installation locations
# =================================================

COMMON_CLAMAV_DIRECTORIES = [
    r"C:\Program Files\ClamAV",
    r"C:\Program Files (x86)\ClamAV",
    r"C:\ClamAV",
]


# =================================================
# ClamAV installation detection
# =================================================

def find_clamav_directory():
    """
    Search common Windows installation locations
    for clamscan.exe and freshclam.exe.

    Return the ClamAV installation directory when
    both executables are found.

    Return None when ClamAV cannot be found.
    """

    for directory in COMMON_CLAMAV_DIRECTORIES:

        clamscan_path = os.path.join(
            directory,
            "clamscan.exe",
        )

        freshclam_path = os.path.join(
            directory,
            "freshclam.exe",
        )

        if (
            os.path.isfile(clamscan_path)
            and os.path.isfile(freshclam_path)
        ):
            return directory

    return None


def get_clamav_executable_paths(
    clamav_directory,
):
    """
    Build the paths to the required ClamAV
    executables.
    """

    clamscan_path = os.path.join(
        clamav_directory,
        "clamscan.exe",
    )

    freshclam_path = os.path.join(
        clamav_directory,
        "freshclam.exe",
    )

    return (
        clamscan_path,
        freshclam_path,
    )


# =================================================
# ClamAV version detection
# =================================================

def get_clamav_version(
    clamscan_path,
):
    """
    Run clamscan --version and return the
    installed ClamAV version.
    """

    try:

        result = subprocess.run(
            [
                clamscan_path,
                "--version",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        output = (
            result.stdout.strip()
            or result.stderr.strip()
        )

        if output:

            return output

    except (
        OSError,
        subprocess.SubprocessError,
    ):

        pass

    return "Version unavailable"


# =================================================
# Virus database validation
# =================================================

def database_is_ready():
    """
    Check whether at least one supported ClamAV
    database file exists in the PegaShield
    database directory.
    """

    database_files = [
        "daily.cvd",
        "daily.cld",
        "main.cvd",
        "main.cld",
        "bytecode.cvd",
        "bytecode.cld",
    ]

    return any(
        os.path.isfile(
            os.path.join(
                DATABASE_DIRECTORY,
                filename,
            )
        )
        for filename in database_files
    )


# =================================================
# Background ClamAV command worker
# =================================================

class CommandWorker(QThread):
    """
    Run ClamAV commands outside the GUI thread.

    This prevents the PegaShield interface from
    freezing during database updates and scans.
    """

    log_signal = Signal(str)

    scan_result_signal = Signal(
        str,
        str,
        str,
    )

    operation_finished = Signal(int)


    def __init__(
        self,
        command,
        operation_type,
    ):

        super().__init__()

        self.command = command

        self.operation_type = (
            operation_type
        )


    def parse_scan_line(
        self,
        line,
    ):
        """
        Parse ClamAV output and emit structured
        clean-file or threat results.
        """

        clean_match = re.match(
            r"^(.*): OK$",
            line,
        )

        if clean_match:

            file_path = (
                clean_match
                .group(1)
                .strip()
            )

            self.scan_result_signal.emit(
                file_path,
                "Clean",
                "",
            )

            return


        threat_match = re.match(
            r"^(.*): (.+) FOUND$",
            line,
        )

        if threat_match:

            file_path = (
                threat_match
                .group(1)
                .strip()
            )

            threat_name = (
                threat_match
                .group(2)
                .strip()
            )

            self.scan_result_signal.emit(
                file_path,
                "Threat detected",
                threat_name,
            )


    def run(
        self,
    ):
        """
        Execute the command and stream its output
        to the PegaShield interface.
        """

        return_code = -1

        try:

            process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                errors="replace",
            )

            if process.stdout:

                for line in process.stdout:

                    clean_line = (
                        line.rstrip()
                    )

                    self.log_signal.emit(
                        clean_line
                    )

                    if (
                        self.operation_type
                        == "scan"
                    ):

                        self.parse_scan_line(
                            clean_line
                        )

            process.wait()

            return_code = (
                process.returncode
            )

            if return_code == 0:

                self.log_signal.emit(
                    "Operation completed "
                    "successfully."
                )

            elif return_code == 1:

                self.log_signal.emit(
                    "WARNING: ClamAV detected "
                    "one or more threats."
                )

            else:

                self.log_signal.emit(
                    "Operation failed with "
                    f"code {return_code}."
                )

        except FileNotFoundError:

            self.log_signal.emit(
                "ERROR: A required ClamAV "
                "executable was not found."
            )

        except Exception as error:

            self.log_signal.emit(
                f"ERROR: {error}"
            )

        self.operation_finished.emit(
            return_code
        )