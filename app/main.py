import os
import re
import sys
import subprocess

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# =================================================
# PegaShield application-data paths
# =================================================

PEGASHIELD_DATA_DIRECTORY = r"C:\ProgramData\PegaShield"

DATABASE_DIRECTORY = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "database",
)

LOG_DIRECTORY = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "logs",
)

QUARANTINE_DIRECTORY = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "quarantine",
)

FRESHCLAM_CONFIG_PATH = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "freshclam.conf",
)


# =================================================
# Common ClamAV installation locations
# =================================================

COMMON_CLAMAV_DIRECTORIES = [
    r"C:\Program Files\ClamAV",
    r"C:\Program Files (x86)\ClamAV",
    r"C:\ClamAV",
]


# =================================================
# ClamAV detection
# =================================================

def find_clamav_directory():

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


def get_clamav_version(clamscan_path):

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

    except Exception:
        pass

    return "Version unavailable"


# =================================================
# Background command worker
# =================================================

class CommandWorker(QThread):

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


    def run(self):

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


# =================================================
# Main application window
# =================================================

class MainWindow(QWidget):

    def __init__(self):

        super().__init__()

        self.worker = None

        self.clamav_directory = None

        self.clamscan_path = None

        self.freshclam_path = None

        self.clean_file_count = 0

        self.threat_count = 0

        self.create_data_directories()

        self.create_freshclam_configuration()

        self.setWindowTitle(
            "PegaShield"
        )

        self.resize(
            1100,
            750,
        )

        self.build_interface()

        self.detect_clamav()


    # =============================================
    # Application setup
    # =============================================

    def create_data_directories(self):

        directories = [
            DATABASE_DIRECTORY,
            LOG_DIRECTORY,
            QUARANTINE_DIRECTORY,
        ]

        for directory in directories:

            os.makedirs(
                directory,
                exist_ok=True,
            )


    def create_freshclam_configuration(self):

        configuration = (
            f"DatabaseDirectory "
            f"{DATABASE_DIRECTORY}\n"
            "DatabaseMirror "
            "database.clamav.net\n"
            "Checks 12\n"
        )

        with open(
            FRESHCLAM_CONFIG_PATH,
            "w",
            encoding="utf-8",
        ) as configuration_file:

            configuration_file.write(
                configuration
            )


    # =============================================
    # Graphical interface
    # =============================================

    def build_interface(self):

        main_layout = QVBoxLayout()

        title = QLabel(
            "PegaShield — Powered by ClamAV"
        )

        self.engine_status_label = QLabel(
            "ClamAV: Checking..."
        )

        self.version_label = QLabel(
            "Engine: Checking..."
        )

        self.database_label = QLabel(
            "Database: Checking..."
        )

        self.operation_status_label = QLabel(
            "Status: Starting..."
        )


        self.update_button = QPushButton(
            "Update Database"
        )

        self.scan_file_button = QPushButton(
            "Scan File"
        )

        self.scan_folder_button = QPushButton(
            "Scan Folder"
        )

        self.clear_results_button = QPushButton(
            "Clear Results"
        )


        action_layout = QHBoxLayout()

        action_layout.addWidget(
            self.update_button
        )

        action_layout.addWidget(
            self.scan_file_button
        )

        action_layout.addWidget(
            self.scan_folder_button
        )

        action_layout.addWidget(
            self.clear_results_button
        )


        self.summary_label = QLabel(
            "Scanned files: 0 | "
            "Clean: 0 | "
            "Threats: 0"
        )


        self.results_table = QTableWidget()

        self.results_table.setColumnCount(
            3
        )

        self.results_table.setHorizontalHeaderLabels(
            [
                "File",
                "Status",
                "Threat",
            ]
        )

        table_header = (
            self.results_table
            .horizontalHeader()
        )

        table_header.setSectionResizeMode(
            0,
            QHeaderView.Stretch,
        )

        table_header.setSectionResizeMode(
            1,
            QHeaderView.ResizeToContents,
        )

        table_header.setSectionResizeMode(
            2,
            QHeaderView.Stretch,
        )

        self.results_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        self.results_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )


        log_title = QLabel(
            "ClamAV Log"
        )

        self.log_output = QTextEdit()

        self.log_output.setReadOnly(
            True
        )


        main_layout.addWidget(
            title
        )

        main_layout.addWidget(
            self.engine_status_label
        )

        main_layout.addWidget(
            self.version_label
        )

        main_layout.addWidget(
            self.database_label
        )

        main_layout.addWidget(
            self.operation_status_label
        )

        main_layout.addLayout(
            action_layout
        )

        main_layout.addWidget(
            self.summary_label
        )

        main_layout.addWidget(
            self.results_table,
            3,
        )

        main_layout.addWidget(
            log_title
        )

        main_layout.addWidget(
            self.log_output,
            2,
        )

        self.setLayout(
            main_layout
        )


        self.update_button.clicked.connect(
            self.update_database
        )

        self.scan_file_button.clicked.connect(
            self.scan_file
        )

        self.scan_folder_button.clicked.connect(
            self.scan_folder
        )

        self.clear_results_button.clicked.connect(
            self.clear_results
        )


    # =============================================
    # Startup diagnostics
    # =============================================

    def detect_clamav(self):

        self.log_output.append(
            "PegaShield startup diagnostics..."
        )

        self.clamav_directory = (
            find_clamav_directory()
        )

        if not self.clamav_directory:

            self.engine_status_label.setText(
                "ClamAV: Not found"
            )

            self.version_label.setText(
                "Engine: Unavailable"
            )

            self.database_label.setText(
                "Database: Unavailable"
            )

            self.operation_status_label.setText(
                "Status: ClamAV installation "
                "required"
            )

            self.set_operation_buttons_enabled(
                False
            )

            self.log_output.append(
                "ERROR: ClamAV was not found."
            )

            return


        self.clamscan_path = os.path.join(
            self.clamav_directory,
            "clamscan.exe",
        )

        self.freshclam_path = os.path.join(
            self.clamav_directory,
            "freshclam.exe",
        )

        version = get_clamav_version(
            self.clamscan_path
        )

        self.engine_status_label.setText(
            "ClamAV: Installed"
        )

        self.version_label.setText(
            f"Engine: {version}"
        )

        if self.database_is_ready():

            self.database_label.setText(
                "Database: Ready"
            )

        else:

            self.database_label.setText(
                "Database: Update required"
            )

        self.operation_status_label.setText(
            "Status: Ready"
        )

        self.log_output.append(
            f"ClamAV detected: "
            f"{self.clamav_directory}"
        )

        self.log_output.append(
            f"Engine: {version}"
        )

        self.log_output.append(
            f"Database directory: "
            f"{DATABASE_DIRECTORY}"
        )

        self.log_output.append(
            "Startup diagnostics completed."
        )


    def database_is_ready(self):

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


    # =============================================
    # Command handling
    # =============================================

    def set_operation_buttons_enabled(
        self,
        enabled,
    ):

        self.update_button.setEnabled(
            enabled
        )

        self.scan_file_button.setEnabled(
            enabled
        )

        self.scan_folder_button.setEnabled(
            enabled
        )


    def start_command(
        self,
        command,
        status,
        operation_type,
    ):

        self.set_operation_buttons_enabled(
            False
        )

        self.operation_status_label.setText(
            status
        )

        self.worker = CommandWorker(
            command,
            operation_type,
        )

        self.worker.log_signal.connect(
            self.append_log
        )

        self.worker.scan_result_signal.connect(
            self.add_scan_result
        )

        self.worker.operation_finished.connect(
            self.command_finished
        )

        self.worker.start()


    # =============================================
    # Database update
    # =============================================

    def update_database(self):

        self.log_output.append(
            "\nStarting database update..."
        )

        command = [
            self.freshclam_path,
            "--config-file",
            FRESHCLAM_CONFIG_PATH,
        ]

        self.start_command(
            command,
            "Status: Updating database...",
            "update",
        )


    # =============================================
    # Scan operations
    # =============================================

    def prepare_new_scan(self):

        self.results_table.setRowCount(
            0
        )

        self.clean_file_count = 0

        self.threat_count = 0

        self.update_summary()


    def scan_file(self):

        file_path, _ = (
            QFileDialog.getOpenFileName(
                self,
                "Select File to Scan",
            )
        )

        if not file_path:

            return

        self.prepare_new_scan()

        self.log_output.append(
            f"\nStarting file scan: "
            f"{file_path}"
        )

        command = [
            self.clamscan_path,
            "--database",
            DATABASE_DIRECTORY,
            file_path,
        ]

        self.start_command(
            command,
            "Status: Scanning file...",
            "scan",
        )


    def scan_folder(self):

        folder_path = (
            QFileDialog.getExistingDirectory(
                self,
                "Select Folder to Scan",
            )
        )

        if not folder_path:

            return

        self.prepare_new_scan()

        self.log_output.append(
            f"\nStarting folder scan: "
            f"{folder_path}"
        )

        command = [
            self.clamscan_path,
            "--recursive",
            "--database",
            DATABASE_DIRECTORY,
            folder_path,
        ]

        self.start_command(
            command,
            "Status: Scanning folder...",
            "scan",
        )


    # =============================================
    # Structured scan results
    # =============================================

    def add_scan_result(
        self,
        file_path,
        status,
        threat_name,
    ):

        row = (
            self.results_table.rowCount()
        )

        self.results_table.insertRow(
            row
        )

        self.results_table.setItem(
            row,
            0,
            QTableWidgetItem(
                file_path
            ),
        )

        self.results_table.setItem(
            row,
            1,
            QTableWidgetItem(
                status
            ),
        )

        self.results_table.setItem(
            row,
            2,
            QTableWidgetItem(
                threat_name
            ),
        )

        if status == "Clean":

            self.clean_file_count += 1

        elif status == "Threat detected":

            self.threat_count += 1

        self.update_summary()


    def update_summary(self):

        total = (
            self.clean_file_count
            + self.threat_count
        )

        self.summary_label.setText(
            f"Scanned files: {total} | "
            f"Clean: "
            f"{self.clean_file_count} | "
            f"Threats: "
            f"{self.threat_count}"
        )


    def clear_results(self):

        self.results_table.setRowCount(
            0
        )

        self.clean_file_count = 0

        self.threat_count = 0

        self.update_summary()


    # =============================================
    # GUI updates
    # =============================================

    def append_log(
        self,
        text,
    ):

        self.log_output.append(
            text
        )


    def command_finished(
        self,
        return_code,
    ):

        self.set_operation_buttons_enabled(
            True
        )

        if return_code == 0:

            self.operation_status_label.setText(
                "Status: Ready"
            )

        elif return_code == 1:

            self.operation_status_label.setText(
                "Status: Threat detected"
            )

        else:

            self.operation_status_label.setText(
                "Status: Operation failed"
            )

        if self.database_is_ready():

            self.database_label.setText(
                "Database: Ready"
            )


# =================================================
# Application entry point
# =================================================

if __name__ == "__main__":

    app = QApplication(
        sys.argv
    )

    window = MainWindow()

    window.show()

    sys.exit(
        app.exec()
    )