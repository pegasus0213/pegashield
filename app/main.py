import json
import os
import shutil
import sys
import uuid

from datetime import datetime

from app.core.clamav import (
    CommandWorker,
    database_is_ready,
    find_clamav_directory,
    get_clamav_executable_paths,
    get_clamav_version,
)

from app.core.paths import (
    DATABASE_DIRECTORY,
    FRESHCLAM_CONFIG_PATH,
    QUARANTINE_DIRECTORY,
    QUARANTINE_METADATA_PATH,
    initialize_application_data,
)

from PySide6.QtCore import Signal

from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# =================================================
# Quarantine data functions
# =================================================

def load_quarantine_records():
    """
    Load quarantine metadata from the JSON file.
    """

    if not os.path.isfile(
        QUARANTINE_METADATA_PATH
    ):
        return []

    try:

        with open(
            QUARANTINE_METADATA_PATH,
            "r",
            encoding="utf-8",
        ) as metadata_file:

            records = json.load(
                metadata_file
            )

        if isinstance(
            records,
            list,
        ):
            return records

    except (
        OSError,
        json.JSONDecodeError,
    ):
        pass

    return []


def save_quarantine_records(
    records,
):
    """
    Save quarantine metadata safely using a
    temporary file.
    """

    temporary_path = (
        QUARANTINE_METADATA_PATH
        + ".tmp"
    )

    with open(
        temporary_path,
        "w",
        encoding="utf-8",
    ) as metadata_file:

        json.dump(
            records,
            metadata_file,
            indent=4,
            ensure_ascii=False,
        )

    os.replace(
        temporary_path,
        QUARANTINE_METADATA_PATH,
    )


# =================================================
# Quarantine Manager
# =================================================

class QuarantineWindow(QWidget):

    quarantine_changed = Signal()


    def __init__(
        self,
    ):

        super().__init__()

        self.records = []

        self.setWindowTitle(
            "PegaShield Quarantine"
        )

        self.resize(
            1000,
            500,
        )

        self.build_interface()

        self.refresh_table()


    def build_interface(
        self,
    ):

        layout = QVBoxLayout()

        title = QLabel(
            "Quarantined Items"
        )

        self.summary_label = QLabel(
            "Items: 0"
        )

        self.table = QTableWidget()

        self.table.setColumnCount(
            4
        )

        self.table.setHorizontalHeaderLabels(
            [
                "Original File",
                "Threat",
                "Date",
                "Quarantine ID",
            ]
        )

        header = (
            self.table
            .horizontalHeader()
        )

        header.setSectionResizeMode(
            0,
            QHeaderView.Stretch,
        )

        header.setSectionResizeMode(
            1,
            QHeaderView.Stretch,
        )

        header.setSectionResizeMode(
            2,
            QHeaderView.ResizeToContents,
        )

        header.setSectionResizeMode(
            3,
            QHeaderView.ResizeToContents,
        )

        self.table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        self.table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        self.restore_button = QPushButton(
            "Restore Selected"
        )

        self.delete_button = QPushButton(
            "Delete Permanently"
        )

        self.refresh_button = QPushButton(
            "Refresh"
        )

        button_layout = QHBoxLayout()

        button_layout.addWidget(
            self.restore_button
        )

        button_layout.addWidget(
            self.delete_button
        )

        button_layout.addWidget(
            self.refresh_button
        )

        layout.addWidget(
            title
        )

        layout.addWidget(
            self.summary_label
        )

        layout.addWidget(
            self.table
        )

        layout.addLayout(
            button_layout
        )

        self.setLayout(
            layout
        )

        self.restore_button.clicked.connect(
            self.restore_selected
        )

        self.delete_button.clicked.connect(
            self.delete_selected
        )

        self.refresh_button.clicked.connect(
            self.refresh_table
        )


    def refresh_table(
        self,
    ):

        self.records = (
            load_quarantine_records()
        )

        self.table.setRowCount(
            0
        )

        for record in self.records:

            row = (
                self.table.rowCount()
            )

            self.table.insertRow(
                row
            )

            self.table.setItem(
                row,
                0,
                QTableWidgetItem(
                    record.get(
                        "original_path",
                        "",
                    )
                ),
            )

            self.table.setItem(
                row,
                1,
                QTableWidgetItem(
                    record.get(
                        "threat_name",
                        "",
                    )
                ),
            )

            self.table.setItem(
                row,
                2,
                QTableWidgetItem(
                    record.get(
                        "quarantined_at",
                        "",
                    )
                ),
            )

            self.table.setItem(
                row,
                3,
                QTableWidgetItem(
                    record.get(
                        "id",
                        "",
                    )
                ),
            )

        self.summary_label.setText(
            f"Items: {len(self.records)}"
        )


    def selected_record(
        self,
    ):

        row = (
            self.table.currentRow()
        )

        if (
            row < 0
            or row >= len(
                self.records
            )
        ):

            QMessageBox.information(
                self,
                "No Selection",
                (
                    "Select a quarantined "
                    "item first."
                ),
            )

            return None

        return self.records[row]


    def restore_selected(
        self,
    ):

        record = (
            self.selected_record()
        )

        if not record:

            return

        original_path = record.get(
            "original_path",
            "",
        )

        quarantine_path = record.get(
            "quarantine_path",
            "",
        )

        if not os.path.isfile(
            quarantine_path
        ):

            QMessageBox.warning(
                self,
                "File Missing",
                (
                    "The quarantined file "
                    "could not be found."
                ),
            )

            return

        warning = QMessageBox.warning(
            self,
            "Restore Threat",
            (
                "This file was detected as:\n\n"
                f"{record.get('threat_name', '')}"
                "\n\nRestoring it may allow "
                "the file to be accessed or "
                "executed again.\n\n"
                "Do you want to continue?"
            ),
            (
                QMessageBox.Yes
                | QMessageBox.No
            ),
            QMessageBox.No,
        )

        if warning != QMessageBox.Yes:

            return

        if os.path.exists(
            original_path
        ):

            overwrite = (
                QMessageBox.question(
                    self,
                    "File Already Exists",
                    (
                        "A file already exists "
                        "at the original path."
                        "\n\nReplace it?"
                    ),
                    (
                        QMessageBox.Yes
                        | QMessageBox.No
                    ),
                    QMessageBox.No,
                )
            )

            if (
                overwrite
                != QMessageBox.Yes
            ):
                return

            if os.path.isdir(
                original_path
            ):

                QMessageBox.warning(
                    self,
                    "Restore Failed",
                    (
                        "The original path is "
                        "currently a directory."
                    ),
                )

                return

            os.remove(
                original_path
            )

        try:

            original_directory = (
                os.path.dirname(
                    original_path
                )
            )

            if original_directory:

                os.makedirs(
                    original_directory,
                    exist_ok=True,
                )

            shutil.move(
                quarantine_path,
                original_path,
            )

            self.records.remove(
                record
            )

            save_quarantine_records(
                self.records
            )

            self.refresh_table()

            self.quarantine_changed.emit()

            QMessageBox.information(
                self,
                "File Restored",
                (
                    "The file was restored "
                    "to:\n\n"
                    f"{original_path}"
                ),
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Restore Failed",
                str(error),
            )


    def delete_selected(
        self,
    ):

        record = (
            self.selected_record()
        )

        if not record:

            return

        confirmation = (
            QMessageBox.warning(
                self,
                "Delete Permanently",
                (
                    "This permanently deletes "
                    "the quarantined file."
                    "\n\nThis action cannot "
                    "be undone."
                    "\n\nContinue?"
                ),
                (
                    QMessageBox.Yes
                    | QMessageBox.No
                ),
                QMessageBox.No,
            )
        )

        if (
            confirmation
            != QMessageBox.Yes
        ):
            return

        quarantine_path = record.get(
            "quarantine_path",
            "",
        )

        try:

            if os.path.isfile(
                quarantine_path
            ):

                os.remove(
                    quarantine_path
                )

            self.records.remove(
                record
            )

            save_quarantine_records(
                self.records
            )

            self.refresh_table()

            self.quarantine_changed.emit()

            QMessageBox.information(
                self,
                "Deleted",
                (
                    "The quarantined file "
                    "was permanently deleted."
                ),
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Delete Failed",
                str(error),
            )


# =================================================
# Main PegaShield window
# =================================================

class MainWindow(QWidget):

    def __init__(
        self,
    ):

        super().__init__()

        self.worker = None

        self.quarantine_window = None

        self.clamav_directory = None

        self.clamscan_path = None

        self.freshclam_path = None

        self.clean_file_count = 0

        self.threat_count = 0

        initialize_application_data()

        self.setWindowTitle(
            "PegaShield"
        )

        self.resize(
            1150,
            780,
        )

        self.build_interface()

        self.detect_clamav()

        self.update_quarantine_count()


    # =============================================
    # Graphical interface
    # =============================================

    def build_interface(
        self,
    ):

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

        self.quarantine_count_label = QLabel(
            "Quarantine: 0 items"
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

        self.quarantine_selected_button = (
            QPushButton(
                "Quarantine Selected"
            )
        )

        self.open_quarantine_button = (
            QPushButton(
                "Open Quarantine"
            )
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
            self.quarantine_selected_button
        )

        action_layout.addWidget(
            self.open_quarantine_button
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

        header = (
            self.results_table
            .horizontalHeader()
        )

        header.setSectionResizeMode(
            0,
            QHeaderView.Stretch,
        )

        header.setSectionResizeMode(
            1,
            QHeaderView.ResizeToContents,
        )

        header.setSectionResizeMode(
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

        main_layout.addWidget(
            self.quarantine_count_label
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

        self.quarantine_selected_button.clicked.connect(
            self.quarantine_selected
        )

        self.open_quarantine_button.clicked.connect(
            self.open_quarantine
        )

        self.clear_results_button.clicked.connect(
            self.clear_results
        )


    # =============================================
    # Startup diagnostics
    # =============================================

    def detect_clamav(
        self,
    ):

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

        (
            self.clamscan_path,
            self.freshclam_path,
        ) = get_clamav_executable_paths(
            self.clamav_directory
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

        if database_is_ready():

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
            "ClamAV detected: "
            f"{self.clamav_directory}"
        )

        self.log_output.append(
            f"Engine: {version}"
        )

        self.log_output.append(
            "Database directory: "
            f"{DATABASE_DIRECTORY}"
        )

        self.log_output.append(
            "Startup diagnostics completed."
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

    def update_database(
        self,
    ):

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

    def prepare_new_scan(
        self,
    ):

        self.results_table.setRowCount(
            0
        )

        self.clean_file_count = 0

        self.threat_count = 0

        self.update_summary()


    def scan_file(
        self,
    ):

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
            "\nStarting file scan: "
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


    def scan_folder(
        self,
    ):

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
            "\nStarting folder scan: "
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


    def update_summary(
        self,
    ):

        total = (
            self.clean_file_count
            + self.threat_count
        )

        self.summary_label.setText(
            f"Scanned files: {total} | "
            f"Clean: {self.clean_file_count} | "
            f"Threats: {self.threat_count}"
        )


    def clear_results(
        self,
    ):

        self.results_table.setRowCount(
            0
        )

        self.clean_file_count = 0

        self.threat_count = 0

        self.update_summary()


    # =============================================
    # Quarantine
    # =============================================

    def quarantine_selected(
        self,
    ):

        row = (
            self.results_table.currentRow()
        )

        if row < 0:

            QMessageBox.information(
                self,
                "No Selection",
                (
                    "Select a detected threat "
                    "from the results table."
                ),
            )

            return

        file_item = (
            self.results_table.item(
                row,
                0,
            )
        )

        status_item = (
            self.results_table.item(
                row,
                1,
            )
        )

        threat_item = (
            self.results_table.item(
                row,
                2,
            )
        )

        if (
            not file_item
            or not status_item
        ):
            return

        file_path = (
            file_item.text()
        )

        status = (
            status_item.text()
        )

        threat_name = (
            threat_item.text()
            if threat_item
            else ""
        )

        if (
            status
            != "Threat detected"
        ):

            QMessageBox.information(
                self,
                "Clean File",
                (
                    "Only detected threats "
                    "can be quarantined."
                ),
            )

            return

        if not os.path.isfile(
            file_path
        ):

            QMessageBox.warning(
                self,
                "File Missing",
                (
                    "The detected file no "
                    "longer exists at:\n\n"
                    f"{file_path}"
                ),
            )

            return

        confirmation = (
            QMessageBox.warning(
                self,
                "Quarantine Threat",
                (
                    "Move this detected file "
                    "to quarantine?\n\n"
                    f"Threat: {threat_name}"
                    "\n\n"
                    f"File: {file_path}"
                ),
                (
                    QMessageBox.Yes
                    | QMessageBox.No
                ),
                QMessageBox.Yes,
            )
        )

        if (
            confirmation
            != QMessageBox.Yes
        ):
            return

        quarantine_id = (
            uuid.uuid4().hex
        )

        quarantine_path = os.path.join(
            QUARANTINE_DIRECTORY,
            f"{quarantine_id}.psq",
        )

        record = {
            "id": quarantine_id,
            "original_path": file_path,
            "quarantine_path": (
                quarantine_path
            ),
            "original_name": (
                os.path.basename(
                    file_path
                )
            ),
            "threat_name": threat_name,
            "quarantined_at": (
                datetime.now()
                .astimezone()
                .isoformat(
                    timespec="seconds"
                )
            ),
        }

        try:

            shutil.move(
                file_path,
                quarantine_path,
            )

            records = (
                load_quarantine_records()
            )

            records.append(
                record
            )

            save_quarantine_records(
                records
            )

            status_item.setText(
                "Quarantined"
            )

            self.operation_status_label.setText(
                "Status: Threat quarantined"
            )

            self.log_output.append(
                "\nThreat quarantined:"
            )

            self.log_output.append(
                file_path
            )

            self.update_quarantine_count()

            QMessageBox.information(
                self,
                "Threat Quarantined",
                (
                    "The detected file was "
                    "moved to quarantine."
                ),
            )

        except Exception as error:

            if (
                os.path.isfile(
                    quarantine_path
                )
                and not os.path.isfile(
                    file_path
                )
            ):

                try:

                    shutil.move(
                        quarantine_path,
                        file_path,
                    )

                except Exception:

                    pass

            QMessageBox.critical(
                self,
                "Quarantine Failed",
                str(error),
            )


    def update_quarantine_count(
        self,
    ):

        records = (
            load_quarantine_records()
        )

        self.quarantine_count_label.setText(
            "Quarantine: "
            f"{len(records)} items"
        )


    def open_quarantine(
        self,
    ):

        self.quarantine_window = (
            QuarantineWindow()
        )

        self.quarantine_window.quarantine_changed.connect(
            self.update_quarantine_count
        )

        self.quarantine_window.show()


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

        if database_is_ready():

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