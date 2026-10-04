import pandas as pd

# ============================================================
# INFECTION PATH ANALYSIS
# ============================================================

web_file = "web_activity/web_activity/data/web_activity.csv"

TARGET_ENDPOINT = "EP4YIFHV"
TARGET_HOST = "host-a616"

DETECTION_TIME = pd.Timestamp(
    "2026-09-11 09:23:33"
)

print("\n================================================")
print("        INFECTION PATH ANALYSIS")
print("================================================")

print("\nTarget endpoint:", TARGET_ENDPOINT)
print("Target host:", TARGET_HOST)
print("Detection time:", DETECTION_TIME)


# ============================================================
# READ WEB LOGS IN CHUNKS
# ============================================================

before_events = []

print("\nScanning web activity...")

for chunk in pd.read_csv(
    web_file,
    chunksize=100000
):

    # Keep only target endpoint
    target = chunk[
        chunk["endpoint_id"] == TARGET_ENDPOINT
    ].copy()

    if len(target) == 0:
        continue

    # Convert timestamp
    target["event_time_parsed"] = pd.to_datetime(
        target["event_time"],
        dayfirst=True,
        errors="coerce"
    )

    # --------------------------------------------------------
    # Only events BEFORE detection
    # --------------------------------------------------------

    before = target[
        target["event_time_parsed"] < DETECTION_TIME
    ].copy()

    if len(before) > 0:
        before_events.append(before)


# ============================================================
# COMBINE RESULTS
# ============================================================

if len(before_events) == 0:

    print("\nNo web activity found before detection.")
    exit()

before_df = pd.concat(
    before_events,
    ignore_index=True
)

before_df = before_df.sort_values(
    "event_time_parsed"
)


# ============================================================
# ONLY SAME-DAY EVENTS
# ============================================================

same_day = before_df[
    before_df["event_time_parsed"].dt.date
    == DETECTION_TIME.date()
].copy()


print("\n================================================")
print("WEB ACTIVITY BEFORE DETECTION")
print("================================================")

print(
    "Total web events before detection:",
    len(before_df)
)

print(
    "Web events on detection day:",
    len(same_day)
)


# ============================================================
# LAST 30 MINUTES BEFORE DETECTION
# ============================================================

window_30 = before_df[
    before_df["event_time_parsed"]
    >= DETECTION_TIME - pd.Timedelta(minutes=30)
].copy()

print("\n================================================")
print("LAST 30 MINUTES BEFORE DETECTION")
print("================================================")

print(
    "Events in last 30 minutes:",
    len(window_30)
)

if len(window_30) > 0:

    print(
        window_30[
            [
                "event_time",
                "log_type",
                "message"
            ]
        ].to_string(index=False)
    )


# ============================================================
# LAST 2 HOURS
# ============================================================

window_2h = before_df[
    before_df["event_time_parsed"]
    >= DETECTION_TIME - pd.Timedelta(hours=2)
].copy()

print("\n================================================")
print("LAST 2 HOURS BEFORE DETECTION")
print("================================================")

print(
    "Events in last 2 hours:",
    len(window_2h)
)


if len(window_2h) > 0:

    print(
        window_2h[
            [
                "event_time",
                "log_type",
                "message"
            ]
        ].to_string(index=False)
    )


# ============================================================
# TOP DESTINATIONS IN LAST 2 HOURS
# ============================================================

print("\n================================================")
print("TOP DESTINATIONS - LAST 2 HOURS")
print("================================================")

if len(window_2h) > 0:

    destinations = (
        window_2h["message"]
        .astype(str)
        .value_counts()
    )

    print(
        destinations.head(30).to_string()
    )


# ============================================================
# ALL DESTINATIONS BEFORE DETECTION
# ============================================================

print("\n================================================")
print("TOP DESTINATIONS - BEFORE DETECTION")
print("================================================")

all_destinations = (
    before_df["message"]
    .astype(str)
    .value_counts()
)

print(
    all_destinations.head(30).to_string()
)


# ============================================================
# LAST WEB EVENT
# ============================================================

print("\n================================================")
print("LAST WEB EVENT BEFORE DETECTION")
print("================================================")

if len(before_df) > 0:

    last_event = before_df.iloc[-1]

    print(
        last_event[
            [
                "event_time",
                "log_type",
                "message"
            ]
        ].to_string()
    )


# ============================================================
# TIME GAP
# ============================================================

if len(before_df) > 0:

    last_time = before_df.iloc[-1]["event_time_parsed"]

    gap = DETECTION_TIME - last_time

    print("\nTime between last web event and detection:")
    print(gap)


# ============================================================
# FINAL
# ============================================================

print("\n================================================")
print("ANALYSIS COMPLETE")
print("================================================")