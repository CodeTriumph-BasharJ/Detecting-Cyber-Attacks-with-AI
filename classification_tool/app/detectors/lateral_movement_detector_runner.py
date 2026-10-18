# Run from project root with the command: python -m classification_tool.app.detectors.lateral_movement_detector_runner

import polars as po
import os
from classification_tool.app.bias_filter.filter import strip_for_detection
from classification_tool.app.detectors.lateral_movement_detector import LateralMovementDetector


def convert_polars_to_dict(data_df: po.DataFrame = po.DataFrame({}), bias_proxy: list = list()) -> list:
  events = data_df.rows(named=True)
  events_stripped = list()

  for event in events:
    events_stripped.append(strip_for_detection(event, bias_proxy))

  return events_stripped


def get_data() -> po.DataFrame:

  database_url = os.getenv("SUPABASE_DB_URL")
  if not database_url:
      raise ValueError("SUPABASE_DB_URL environment variable is not set.")
  data_df = po.read_database_uri(uri=database_url, query=""" SELECT * FROM "Dummy_Data" where action = 'ssh_connect' """)

  return data_df


def get_lateral_movement_attacks(bias_proxy: list = list()) -> tuple:
  data = get_data()
  json_data = convert_polars_to_dict(data, bias_proxy)

  detector = LateralMovementDetector()
  incidents = detector.scan(json_data)

  return incidents, data.select(["user_id", "department", "seniority"])

'''
print(get_lateral_movement_attacks()[0])
'''