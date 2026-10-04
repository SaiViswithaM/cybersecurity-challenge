import pandas as pd

# ============================================================
# COMMON MALICIOUS ARTIFACT ANALYSIS
# ============================================================

file_path = "web_activity/web_activity/data/endpoint_security.csv"

print("\n===== LOADING ENDPOINT SECURITY LOG =====")

df = pd.read_csv(file_path)

print("Total records:", len(df))


# ============================================================
# FIND MALICIOUS EVENTS
# ============================================================

malicious = df[
    df["message"]
    .astype(str)
    .str.contains(
        "FileType: Malicious",
        case=False,
        na=False
    )
].copy()

print("\n===== MALICIOUS EVENTS =====")
print("Total malicious records:", len(malicious))


# ============================================================
# EXTRACT SHA256
# ============================================================

malicious["sha256"] = (
    malicious["message"]
    .astype(str)
    .str.extract(
        r"SHA256:\s*([a-fA-F0-9]+)",
        expand=False
    )
)

# Extract filename
malicious["filename"] = (
    malicious["message"]
    .astype(str)
    .str.extract(
        r"File:\s*(.*?)\s*\|\s*Quarantined At:",
        expand=False
    )
)


# ============================================================
# MOST COMMON SHA256 HASHES
# ============================================================

print("\n===== MOST COMMON MALICIOUS SHA256 HASHES =====")

hash_counts = (
    malicious["sha256"]
    .value_counts()
)

print(hash_counts.head(20).to_string())


# ============================================================
# REPEATED HASHES
# ============================================================

print("\n===== REPEATED MALICIOUS HASHES =====")

repeated_hashes = hash_counts[
    hash_counts > 1
]

print(
    "Number of repeated hashes:",
    len(repeated_hashes)
)

print(
    repeated_hashes.to_string()
)


# ============================================================
# DETAILS FOR EACH REPEATED HASH
# ============================================================

print("\n===== DETAILS OF REPEATED HASHES =====")

for hash_value in repeated_hashes.index:

    print("\n----------------------------------------")
    print("SHA256:", hash_value)
    print(
        "Number of records:",
        repeated_hashes[hash_value]
    )

    records = malicious[
        malicious["sha256"] == hash_value
    ]

    print(
        records[
            [
                "endpoint_id",
                "endpoint_name",
                "event_time",
                "filename",
                "message"
            ]
        ]
        .to_string(index=False)
    )


# ============================================================
# MOST COMMON MALICIOUS FILENAMES
# ============================================================

print("\n===== MOST COMMON MALICIOUS FILENAMES =====")

filename_counts = (
    malicious["filename"]
    .value_counts()
)

print(
    filename_counts.head(30).to_string()
)


# ============================================================
# HOSTS ASSOCIATED WITH REPEATED HASHES
# ============================================================

print("\n===== HOSTS WITH REPEATED MALICIOUS HASHES =====")

if len(repeated_hashes) > 0:

    repeated_records = malicious[
        malicious["sha256"].isin(
            repeated_hashes.index
        )
    ]

    host_summary = (
        repeated_records
        .groupby(
            [
                "endpoint_id",
                "endpoint_name"
            ]
        )
        .size()
        .sort_values(ascending=False)
    )

    print(
        host_summary.to_string()
    )


# ============================================================
# SPECIFIC ARTIFACT
# ============================================================

target_hash = (
    "5e10b3490160cca0fc872f2b026d4b40bafc236852f83d30c9031899e50adc9c"
)

print("\n===== SPECIFIC ARTIFACT ANALYSIS =====")

target = malicious[
    malicious["sha256"] == target_hash
]

print(
    "Target SHA256:",
    target_hash
)

print(
    "Number of records:",
    len(target)
)

if len(target) > 0:

    print(
        target[
            [
                "endpoint_id",
                "endpoint_name",
                "event_time",
                "filename",
                "message"
            ]
        ]
        .to_string(index=False)
    )

else:

    print("Target hash was not found.")


print("\n===== ANALYSIS COMPLETE =====")