import json
import os
from datetime import datetime

from app.core.paths import (
    SCAN_HISTORY_PATH,
)


# =================================================
# Scan-history storage
# =================================================

def load_scan_history():
    """
    Load all saved scan records.

    Return an empty list if the history file does
    not exist or cannot be read.
    """

    if not os.path.isfile(
        SCAN_HISTORY_PATH
    ):

        return []

    try:

        with open(
            SCAN_HISTORY_PATH,
            "r",
            encoding="utf-8",
        ) as history_file:

            records = json.load(
                history_file
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


def save_scan_history(
    records,
):
    """
    Save all scan-history records.
    """

    history_directory = os.path.dirname(
        SCAN_HISTORY_PATH
    )

    os.makedirs(
        history_directory,
        exist_ok=True,
    )

    temporary_path = (
        SCAN_HISTORY_PATH
        + ".tmp"
    )

    with open(
        temporary_path,
        "w",
        encoding="utf-8",
    ) as history_file:

        json.dump(
            records,
            history_file,
            indent=4,
            ensure_ascii=False,
        )

    os.replace(
        temporary_path,
        SCAN_HISTORY_PATH,
    )


def add_scan_record(
    target_path,
    scan_type,
    clean_count,
    threat_count,
    result,
):
    """
    Add one completed scan to persistent history.
    """

    records = load_scan_history()

    record = {
        "date": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "target": target_path,
        "scan_type": scan_type,
        "clean_count": clean_count,
        "threat_count": threat_count,
        "result": result,
    }

    records.insert(
        0,
        record,
    )

    save_scan_history(
        records
    )

    return record


def clear_scan_history():
    """
    Remove all saved scan records.
    """

    save_scan_history(
        []
    )