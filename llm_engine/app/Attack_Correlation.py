import re
import polars as po

class Attack_Correlation:

    def __init__(self):
        return

    '''
    Function that finds the attack incidents sharing the same user and session IDs and concatenates their JSON strings.

    Input: Brute-Force, Data-Exfiltration, Lateral-Movement, and Privilege-Escalation Lists of JSON attack strings.
    Output: List of correlated and concatenated JSON attack strings.
    '''
    def check_correlation(self, brute_force : list = list(), data_exfiltration : list = list(),
                          lateral_movement : list = list(), privilege_escalation : list = list()) -> list:

        atk_user_session_id = {}
        

        atk_user_session_id = {
            f"{user_id.group()}:{sess_id.group()}:bf": atk
            for atk in brute_force
            if (user_id := re.search(r"u\d+_\w+", atk))
            and (sess_id := re.search(r"sess\d+", atk))
        }

        atk_user_session_id |= {
            f"{user_id.group()}:{sess_id.group()}:de": atk
            for atk in data_exfiltration
            if (user_id := re.search(r"u\d+_\w+", atk))
            and (sess_id := re.search(r"sess\d+", atk))
        }

        atk_user_session_id |= {
            f"{user_id.group()}:{sess_id.group()}:lm": atk
            for atk in lateral_movement
            if (user_id := re.search(r"u\d+_\w+", atk))
            and (sess_id := re.search(r"sess\d+", atk))
        }

        atk_user_session_id |= {
            f"{user_id.group()}:{sess_id.group()}:pe": atk
            for atk in privilege_escalation
            if (user_id := re.search(r"u\d+_\w+", atk))
            and (sess_id := re.search(r"sess\d+", atk))
        }
        
        user_ids = list()
        session_ids = list()

        #print(atk_user_session_id.keys())

        for key in atk_user_session_id.keys():
            elements = key.split(":")
            user_ids.append(elements[0])
            session_ids.append(elements[1])

        correlated_atks = list()

        checked_user_session = {}

        for user_id, session_id in zip(user_ids, session_ids):
            atk_str = ""

            if checked_user_session.get(user_id + ":" + session_id, 0) == 0:
                checked_user_session[user_id + ":" + session_id] = 1
                
                for atk_type in ["bf", "de", "lm", "pe"]:
                    atk_json = atk_user_session_id.get(user_id + ":" + session_id + f":{atk_type}", "")
                    if len(atk_json) > 0:
                        atk_str += atk_json

                atks = atk_str.split("\n\nEnd of Attack\n\n")
                if len(atks) >= 2 and len(atks[1]) > 0:
                    correlated_atks.extend([atk + "\n\nEnd of Attack\n\n" for atk in atks if len(atk) > 0])
                    
        if len(correlated_atks) < 2:
            return list()

        #print("".join(correlated_atks))
        #print([re.findall(r'"attack_type":\s*"([^"]+)"', atk)[0] for atk in correlated_atks])
        
        return correlated_atks