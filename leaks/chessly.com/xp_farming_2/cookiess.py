
import random , time
def generate_ga_cookies(
    property_id: str,
    client_id: int = None,
    first_visit_timestamp: int = None,
    session_count: int = 1,
    engaged: bool = True,
    session_duration: int = None,
    event_count: int = None,
    cross_domain: int = 0,
    reserved: int = 0
) -> str:
    if client_id is None:
        client_id = random.randint(100_000_000, 1_999_999_999)
    if first_visit_timestamp is None:
        first_visit_timestamp = int(time.time())
    if session_duration is None:
        session_duration = random.randint(1_800, 10_800)
    if event_count is None:
        event_count = random.randint(20, 80)

    session_start = first_visit_timestamp - 1
    last_event = session_start + session_duration
    g_flag = 1 if engaged else 0

    ga = f"GA1.1.{client_id}.{first_visit_timestamp}"
    gapn = (f"GS2.1.s{session_start}$o{session_count}"
            f"$g{g_flag}$t{last_event}$j{event_count}$l{cross_domain}$h{reserved}")

    return f"_ga={ga}; _ga_{property_id}={gapn};"
