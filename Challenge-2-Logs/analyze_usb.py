import pandas as pd

usb_file = "web_activity/web_activity/data/usb_events.csv"

print("\n===== LOADING USB EVENTS =====")

df = pd.read_csv(usb_file)

print("\n===== COLUMNS =====")
print(df.columns.tolist())

print("\n===== TOTAL USB EVENTS =====")
print(len(df))

print("\n===== FIRST 20 USB EVENTS =====")
print(df.head(20).to_string(index=False))

print("\n===== USB EVENTS BY ENDPOINT =====")
print(
    df["endpoint_name"]
    .value_counts()
    .head(30)
)

print("\n===== USB EVENTS BY DEVICE TYPE =====")

if "device_type" in df.columns:
    print(df["device_type"].value_counts())

elif "message" in df.columns:
    print(df["message"].value_counts().head(30))

print("\n===== USB EVENTS FOR HOST-A616 =====")

host = df[
    df.astype(str)
    .apply(
        lambda row: row.str.contains(
            "host-a616",
            case=False,
            na=False
        ).any(),
        axis=1
    )
]

print("Events for host-a616:", len(host))

if len(host) > 0:
    print(host.to_string(index=False))

print("\n===== USB ANALYSIS COMPLETE =====")