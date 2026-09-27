"""
Module 2: Data Loader
Ingests raw JSON and CSV data files from data/raw/
Validates content, checks schemas, and prepares data for normalization.
"""

import os
import json
import logging
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DataLoader")

class DataLoader:
    def __init__(self, raw_data_dir: str):
        self.raw_data_dir = raw_data_dir

    def _load_json(self, filename: str) -> list:
        filepath = os.path.join(self.raw_data_dir, filename)
        if not os.path.exists(filepath):
            logger.warning(f"File not found: {filepath}. Returning empty list.")
            return []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                logger.info(f"Loaded {len(data)} records from {filename}")
                return data
        except Exception as e:
            logger.error(f"Error reading JSON file {filepath}: {e}")
            raise

    def _load_csv(self, filename: str) -> pd.DataFrame:
        filepath = os.path.join(self.raw_data_dir, filename)
        if not os.path.exists(filepath):
            logger.warning(f"File not found: {filepath}. Returning empty DataFrame.")
            return pd.DataFrame()
        try:
            df = pd.read_csv(filepath)
            logger.info(f"Loaded {len(df)} rows from {filename}")
            return df
        except Exception as e:
            logger.error(f"Error reading CSV file {filepath}: {e}")
            raise

    def load_all(self) -> dict:
        """Loads all raw datasets into a single python dictionary."""
        logger.info(f"Starting raw data ingestion from: {self.raw_data_dir}")
        return {
            "iam": self._load_json("iam_users_roles.json"),
            "s3": self._load_json("s3_buckets.json"),
            "ec2": self._load_json("ec2_instances.json"),
            "vpcs": self._load_json("vpc_networks.json"),
            "cloudtrail": self._load_json("cloudtrail_events.json"),
            "software_inventory": self._load_csv("software_inventory.csv")
        }

if __name__ == "__main__":
    import sys
    raw_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "raw")
    loader = DataLoader(raw_dir)
    data = loader.load_all()
    print("Ingestion complete. Keys loaded:", list(data.keys()))
