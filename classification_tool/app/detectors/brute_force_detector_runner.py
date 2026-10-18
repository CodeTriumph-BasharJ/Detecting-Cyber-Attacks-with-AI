# Run from project root with the command: python -m classification_tool.app.detectors.brute_force_detector_runner
# May need to fix the import in generate_attack_corpus.py

import polars as po
import os
from classification_tool.app.detectors.brute_force_detector import BruteForceDetector
from classification_tool.app.bias_filter.filter import strip_for_detection

def convert_polars_to_dict(data_df : po.DataFrame = po.DataFrame({}), bias_proxy : list = list()) -> list:
  events = data_df.rows(named=True)
  events_stripped = list()

  #Pass data through bias filter
  for event in events:
    events_stripped.append(strip_for_detection(event, bias_proxy))

  return events_stripped

def get_data() -> po.DataFrame:
  #Can be modified to default to local data in case Supabase goes offline
  
  database_url = os.getenv("SUPABASE_DB_URL")
  

  if not database_url:
      raise ValueError("SUPABASE_DB_URL environment variable is not set.")
  data_df = po.read_database_uri(uri= database_url, query = """ SELECT * FROM "Dummy_Data" where action = 'login' """)

  return data_df

def get_brute_force_attacks(bias_proxy : list = list()) -> tuple:
  data = get_data()
  json_data = convert_polars_to_dict(data, bias_proxy)
  instance = "BRUTE_FORCE"

  detector = BruteForceDetector()
  incidents = detector.scan(json_data)

  return incidents, data.select(["user_id", "department", "seniority"])

'''
print(get_brute_force_attacks()[0][0])
'''