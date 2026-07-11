import os

from PySide6.QtCore import Signal

from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.services.quarantine import (
    delete_quarantined_file,
    load_quarantine_records,
    restore_quarantined_file,
)


class QuarantineWindow(QWidget):
    """
    Display and manage files stored in the
    PegaShield quarantine.
    """

    quarantine_changed = Signal()


    def __init__(self):

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


    def build_interface(self):

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

        self.table.setSelectionMode(
            QTableWidget.SingleSelection
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


    def refresh_table(self):

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


    def selected_record(self):

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


    def restore_selected(self):

        record = (
            self.selected_record()
        )

        if not record:

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

        overwrite = False

        original_path = record.get(
            "original_path",
            "",
        )

        if os.path.exists(
            original_path
        ):

            overwrite_answer = (
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
                overwrite_answer
                != QMessageBox.Yes
            ):

                return

            overwrite = True

        try:

            restored_path = (
                restore_quarantined_file(
                    record,
                    overwrite=overwrite,
                )
            )

            self.refresh_table()

            self.quarantine_changed.emit()

            QMessageBox.information(
                self,
                "File Restored",
                (
                    "The file was restored "
                    "to:\n\n"
                    f"{restored_path}"
                ),
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Restore Failed",
                str(error),
            )


    def delete_selected(self):

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

        try:

            delete_quarantined_file(
                record
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