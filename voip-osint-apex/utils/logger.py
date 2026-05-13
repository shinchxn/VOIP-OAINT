import logging
import os
from datetime import datetime

os.makedirs("outputs/logs", exist_ok=True)
date_str = datetime.now().strftime("%Y-%m-%d")
log_file = f"outputs/logs/audit_{date_str}.log"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

def log_action(cmd, input_val, result, modules, report_file=None):
    msg = f"CMD:{cmd}\n  INPUT: {input_val}\n  RESULT: {result}\n  MODULES: {modules}"
    if report_file:
        msg += f"\n  REPORT: {report_file}"
    logging.info(msg)
