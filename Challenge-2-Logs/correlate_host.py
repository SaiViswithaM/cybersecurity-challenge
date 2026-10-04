import pandas as pd

# ============================================================
# CORRELATE HOST-A616 WITH WEB ACTIVITY
# ============================================================

web_file = "web_activity/web_activity/data/web_activity.csv"

target_endpoint = "EP4YIFHV"

matches = []

print("\n===== SCANNING WEB ACTIVITY =====")

for chunk in pd.read_csv(
    web_file,
    chunksize=100000
):

    matched = chunk[
        chunk["endpoint_id"] == target_endpoint
    ].copy()

    if len(matched) > 0:
        matches.append(matched)


if not matches:

    print("No records found.")
    exit()


web = pd.concat(
    matches,
    ignore_index=True
)

# Convert timestamps
web["event_time"] = pd.to_datetime(
    web["event_time"],
    dayfirst=True,
    errors="coerce"
)

# ============================================================
# 1. ALL EVENTS ON 11 SEPTEMBER
# ============================================================

print("\n===== HOST-A616 WEB ACTIVITY ON 11-09-2026 =====")

day = web[
    (web["event_time"] >= "2026-09-11 00:00:00") &
    (web["event_time"] < "2026-09-12 00:00:00")
].copy()

print("Total events:", len(day))

if len(day) > 0:

    print(
        day[
            [
                "event_time",
                "message"
            ]
        ]
        .sort_values("event_time")
        .to_string(index=False)
    )


# ============================================================
# 2. EVENTS IMMEDIATELY BEFORE MALICIOUS DETECTION
# ============================================================

print(
    "\n===== EVENTS BEFORE MALICIOUS DETECTION ====="
)

before = web[
    (web["event_time"] >= "2026-09-11 08:00:00") &
    (web["event_time"] < "2026-09-11 09:23:33")
].copy()

print("Total events:", len(before))

if len(before) > 0:

    print(
        before[
            [
                "event_time",
                "message"
            ]
        ]
        .sort_values("event_time")
        .to_string(index=False)
    )


# ============================================================
# 3. EVENTS AROUND DETECTION
# ============================================================

print(
    "\n===== EVENTS AROUND DETECTION ====="
)

around = web[
    (web["event_time"] >= "2026-09-11 09:20:00") &
    (web["event_time"] <= "2026-09-11 09:40:00")
].copy()

print("Total events:", len(around))

if len(around) > 0:

    print(
        around[
            [
                "event_time",
                "message"
            ]
        ]
        .sort_values("event_time")
        .to_string(index=False)
    )


# ============================================================
# 4. EVENTS AFTER DETECTION
# ============================================================

print(
    "\n===== EVENTS AFTER DETECTION ====="
)

after = web[
    (web["event_time"] > "2026-09-11 09:35:09") &
    (web["event_time"] <= "2026-09-11 12:00:00")
].copy()

print("Total events:", len(after))

if len(after) > 0:

    print(
        after[
            [
                "event_time",
                "message"
            ]
        ]
        .sort_values("event_time")
        .to_string(index=False)
    )


# ============================================================
# 5. UNIQUE DESTINATIONS BEFORE DETECTION
# ============================================================

print(
    "\n===== TOP DESTINATIONS BEFORE DETECTION ====="
)

if len(before) > 0:

    print(
        before["message"]
        .astype(str)
        .value_counts()
        .head(30)
    )


print(
    "\n===== CORRELATION COMPLETE ====="
)