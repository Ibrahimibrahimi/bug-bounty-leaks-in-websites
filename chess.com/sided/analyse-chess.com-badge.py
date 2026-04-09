import uuid
from datetime import datetime, timezone

def parse_uuid_v1(uuid_str):
    u = uuid.UUID(uuid_str)

    assert u.version == 1, "Not a UUID v1!"

    # Timestamp: 100ns intervals since 1582-10-15
    GREGORIAN_OFFSET = 0x01b21dd213814000
    unix_ts = (u.time - GREGORIAN_OFFSET) / 1e7
    dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)

    print(f"UUID        : {u}")
    print(f"Version     : {u.version}")
    print(f"time_low    : {u.time_low:#010x}")
    print(f"time_mid    : {u.time_mid:#06x}")
    print(f"time_hi     : {u.time_hi_version:#06x}")
    print(f"clock_seq   : {u.clock_seq:#06x}")
    print(f"node        : {u.node:#014x}")
    print(f"Generated at: {dt}")
    print()


us = [
"abea117e-2af1-11ee-93f0-1f375626db21",
"abea13cc-2af1-11ee-b8a8-0710e9c93295",
"abea1624-2af1-11ee-b605-530cf2dfaa9a",
"abdd2734-2af1-11ee-8244-4f1664a08e5b",
"abdd24fa-2af1-11ee-86a9-47c46b88f3ff",
"abdd24fa-2af1-11ee-86a9-47c46b88f3ff"
]
#ith open("uuids.txt","r") as file :
#	us = file.readlines()


# extract info for each one
for i in us :
	print("="*10,"(",i,")","="*10)
	parse_uuid_v1(i)
	print("\n"*3)
