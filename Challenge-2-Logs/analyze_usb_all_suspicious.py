import pandas as pd

endpoint_file = "web_activity/web_activity/data/endpoint_security.csv"
usb_file = "web_activity/web_activity/data/usb_events.csv"

print("\n===== USB CORRELATION WITH SUSPICIOUS ENDPOINTS =====")

# Load endpoint security logs
endpoint_df = pd.read_csv(endpoint_file)

# Find malicious events
malicious = endpoint_df[
    endpoint_df["message"]
    .astype(str)
    .str.contains(
        "FileType: Malicious",
        case=False,
        na=False
    )
]

# Get all suspicious endpoints
suspicious_endpoints = malicious["endpoint_id"].unique()

print(
    "\nNumber of suspicious endpoints:",
    len(suspicious_endpoints)
)

print(
    "Suspicious endpoint IDs:"
)

print(
    list(suspicious_endpoints)
)


# ------------------------------------------------------------
# Load USB events
# ------------------------------------------------------------

usb = pd.read_csv(usb_file)

print(
    "\nTotal USB events in dataset:",
    len(usb)
)


# ------------------------------------------------------------
# Match USB events against suspicious endpoints
# ------------------------------------------------------------

suspicious_usb = usb[
    usb["endpoint_id"].isin(suspicious_endpoints)
].copy()


print(
    "\n===== USB EVENTS ON SUSPICIOUS ENDPOINTS ====="
)

print(
    "Matching USB events:",
    len(suspicious_usb)
)


if len(suspicious_usb) > 0:

    print(
        suspicious_usb.to_string(index=False)
    )

else:

    print(
        "No USB events were recorded for the suspicious endpoints."
    )


# ------------------------------------------------------------
# USB endpoints
# ------------------------------------------------------------

print(
    "\n===== USB ENDPOINT SUMMARY ====="
)

if len(suspicious_usb) > 0:

    summary = (
        suspicious_usb
        .groupby(
            ["endpoint_id", "endpoint_name"]
        )
        .size()
        .sort_values(ascending=False)
    )

    print(
        summary.to_string()
    )

else:

    print(
        "No suspicious endpoints have USB activity."
    )


# ------------------------------------------------------------
# Compare all USB endpoints with suspicious endpoints
# ------------------------------------------------------------

print(
    "\n===== ALL USB EVENTS ====="
)

print(
    usb.to_string(index=False)
)


print(
    "\n===== ANALYSIS COMPLETE ====="
)