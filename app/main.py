import sys

from PySide6.QtWidgets import (
    QApplication,
)

from app.gui.main_window import (
    MainWindow,
)


def main():
    """
    Start the PegaShield desktop application.
    """

    application = QApplication(
        sys.argv
    )

    application.setApplicationName(
        "PegaShield"
    )

    application.setOrganizationName(
        "PegaShield"
    )

    window = MainWindow()

    window.show()

    return application.exec()


if __name__ == "__main__":

    sys.exit(
        main()
    )