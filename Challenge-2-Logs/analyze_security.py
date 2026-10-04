import pandas as pd

# ============================================================
# 1. ENDPOINT SECURITY LOG ANALYSIS
# ============================================================

file_path = "web_activity/web_activity/data/endpoint_security.csv"

# Read endpoint security log
df = pd.read_csv(file_path)

print("\n===== DATASET INFORMATION =====")
print("Number of rows:", len(df))
print("Number of columns:", len(df.columns))

print("\n===== COLUMN NAMES =====")

for column in df.columns:
    print(column)


print("\n===== FIRST 5 ROWS =====")

print(df.head())


print("\n===== LOG TYPES =====")

print(
    df["log_type"]
    .value_counts()
)


# ============================================================
# 1A. FIND MALICIOUS EVENTS
# ============================================================

print("\n===== MALICIOUS EVENTS =====")

malicious = df[
    df["message"]
    .astype(str)
    .str.contains(
        "FileType: Malicious",
        case=False,
        na=False
    )
]

print(
    "Number of malicious events:",
    len(malicious)
)


print("\n===== ENDPOINTS WITH MALICIOUS EVENTS =====")

print(
    malicious["endpoint_id"]
    .value_counts()
)


print("\n===== HOSTS WITH MALICIOUS EVENTS =====")

print(
    malicious["endpoint_name"]
    .value_counts()
)


# ============================================================
# 2. MALICIOUS FILE DETAILS
# ============================================================

print("\n===== MALICIOUS FILE DETAILS =====")

for index, row in malicious.iterrows():

    print("\n-----------------------------------")

    print("Endpoint:", row["endpoint_id"])
    print("Host:", row["endpoint_name"])
    print("Time:", row["event_time"])
    print("Message:", row["message"])


# ============================================================
# 3. CHECK WEB ACTIVITY CSV
# ============================================================

print("\n===== CHECKING WEB ACTIVITY FILE =====")

web_file = "web_activity/web_activity/data/web_activity.csv"

# IMPORTANT:
# The web_activity.csv is very large.
# Read only 5 rows to inspect its structure.

web_sample = pd.read_csv(
    web_file,
    nrows=5
)


print("\n===== WEB ACTIVITY COLUMN NAMES =====")

for column in web_sample.columns:
    print(column)


print("\n===== FIRST 5 WEB ACTIVITY ROWS =====")

print(
    web_sample.to_string(index=False)
)


# ============================================================
# 4. WEB ACTIVITY OF MALICIOUS ENDPOINTS
# ============================================================

print("\n===== WEB ACTIVITY OF MALICIOUS ENDPOINTS =====")

# Get unique endpoints that had malicious detections

malicious_endpoints = malicious[
    "endpoint_id"
].unique()


print(
    "Number of suspicious endpoints:",
    len(malicious_endpoints)
)


print("\nSuspicious endpoints:")

print(malicious_endpoints)


# ------------------------------------------------------------
# Read the huge web_activity.csv in chunks
# ------------------------------------------------------------

matches = []

for chunk in pd.read_csv(
    web_file,
    chunksize=100000
):

    matched = chunk[
        chunk["endpoint_id"]
        .isin(malicious_endpoints)
    ]

    if len(matched) > 0:

        matches.append(
            matched
        )


# ------------------------------------------------------------
# Combine matching records
# ------------------------------------------------------------

if matches:

    web_matches = pd.concat(
        matches,
        ignore_index=True
    )


    print("\n===== MATCHING WEB ACTIVITY RECORDS =====")

    print(
        "Number of matching web activity records:",
        len(web_matches)
    )


    print("\n===== WEB ACTIVITY BY ENDPOINT =====")

    print(
        web_matches["endpoint_name"]
        .value_counts()
    )


    print("\n===== TOP DOMAINS / IPs =====")

    print(
        web_matches["message"]
        .astype(str)
        .value_counts()
        .head(50)
    )

else:

    print(
        "No matching web activity found."
    )


# ============================================================
# 5. CORRELATION ANALYSIS FOR HOST-A616
# ============================================================

print(
    "\n===== CORRELATION ANALYSIS: HOST-A616 ====="
)


# Target endpoint

target_endpoint = "EP4YIFHV"


# Store only records belonging to target endpoint

target_matches = []


# ------------------------------------------------------------
# Read web_activity.csv in chunks
# ------------------------------------------------------------

for chunk in pd.read_csv(
    web_file,
    chunksize=100000
):

    matched = chunk[
        chunk["endpoint_id"]
        == target_endpoint
    ].copy()


    if len(matched) > 0:

        target_matches.append(
            matched
        )


# ============================================================
# COMBINE TARGET RECORDS
# ============================================================

if target_matches:

    target_web = pd.concat(
        target_matches,
        ignore_index=True
    )


    # ========================================================
    # 5A. TARGET HOST SUMMARY
    # ========================================================

    print("\n===== TARGET HOST SUMMARY =====")

    print(
        "Endpoint:",
        target_endpoint
    )


    print(
        "Host:",
        target_web["endpoint_name"].iloc[0]
    )


    print(
        "Total web activity records:",
        len(target_web)
    )


    # ========================================================
    # 5B. CONVERT EVENT TIME
    # ========================================================

    target_web["event_time"] = pd.to_datetime(
        target_web["event_time"],
        dayfirst=True,
        errors="coerce"
    )


    # ========================================================
    # 5C. WEB LOG TYPES
    # ========================================================

    print("\n===== WEB LOG TYPES =====")

    print(
        target_web["log_type"]
        .value_counts()
    )


    # ========================================================
    # 5D. WEB ACTIVITY BY DATE
    # ========================================================

    print("\n===== WEB ACTIVITY BY DATE =====")

    target_web["date"] = (
        target_web["event_time"]
        .dt.date
    )


    print(
        target_web["date"]
        .value_counts()
        .sort_index()
    )


    # ========================================================
    # 5E. TOP DOMAINS / IPs
    # ========================================================

    print("\n===== TOP DOMAINS / IPs =====")

    print(
        target_web["message"]
        .astype(str)
        .value_counts()
        .head(20)
    )


    # ========================================================
    # 5F. WEB BLOCK EVENTS
    # ========================================================

    print("\n===== WEB BLOCK EVENTS =====")

    web_block = target_web[
        target_web["log_type"]
        .astype(str)
        .str.contains(
            "block",
            case=False,
            na=False
        )
    ]


    print(
        "Number of web block events:",
        len(web_block)
    )


    if len(web_block) > 0:

        print(
            web_block[
                [
                    "endpoint_id",
                    "endpoint_name",
                    "event_time",
                    "log_type",
                    "message"
                ]
            ].to_string(index=False)
        )

    else:

        print(
            "No web block events found."
        )


    # ========================================================
    # 5G. WEB ACTIVITY AROUND FIRST MALICIOUS DETECTION
    # ========================================================

    print(
        "\n===== ALL WEB ACTIVITY AROUND FIRST DETECTION ====="
    )


    # The first malicious detections for host-a616
    # occurred around 11-09-2026 09:23:33.
    #
    # We examine one hour before and after this period.

    around_detection = target_web[
        (
            target_web["event_time"]
            >= "2026-09-11 08:00:00"
        )
        &
        (
            target_web["event_time"]
            <= "2026-09-11 10:00:00"
        )
    ].copy()


    print(
        "Number of web events between 08:00 and 10:00:",
        len(around_detection)
    )


    if len(around_detection) > 0:

        print(
            around_detection[
                [
                    "endpoint_id",
                    "endpoint_name",
                    "event_time",
                    "log_type",
                    "message"
                ]
            ].to_string(index=False)
        )

    else:

        print(
            "No web activity found in this time window."
        )


    # ========================================================
    # 5H. WEB ACTIVITY BEFORE MALICIOUS DETECTION
    # ========================================================

    print(
        "\n===== WEB ACTIVITY BEFORE DETECTION ====="
    )


    before_detection = target_web[
        (
            target_web["event_time"]
            >= "2026-09-11 00:00:00"
        )
        &
        (
            target_web["event_time"]
            < "2026-09-11 09:23:33"
        )
    ].copy()


    print(
        "Number of web events before 09:23:33:",
        len(before_detection)
    )


    if len(before_detection) > 0:

        print(
            before_detection[
                [
                    "event_time",
                    "message"
                ]
            ].to_string(index=False)
        )

    else:

        print(
            "No web activity before the detection time."
        )


    # ========================================================
    # 5I. DESTINATIONS BEFORE DETECTION
    # ========================================================

    print(
        "\n===== DESTINATIONS BEFORE DETECTION ====="
    )


    if len(before_detection) > 0:

        print(
            before_detection["message"]
            .astype(str)
            .value_counts()
            .head(30)
        )

    else:

        print(
            "No destinations available."
        )


else:

    print(
        "No web activity found for target endpoint."
    )


# ============================================================
# END OF ANALYSIS
# ============================================================

print(
    "\n===== ANALYSIS COMPLETED ====="
)