from datetime import datetime, timezone

def scan_iam_findings(session):
    client = session.client("iam")
    findings = []

    users = client.list_users()["Users"]

    for user in users:
        username = user["UserName"]

        # MFA check (high)
        mfa = client.list_mfa_devices(UserName=username)
        if len(mfa["MFADevices"]) == 0:
            findings.append((f"{username} has no MFA", "High"))

        # Access key age check (Medium)
        keys = client.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for key in keys:
            age = (datetime.now(timezone.utc) - key["CreateDate"]).days
            if age > 90:
                findings.append((f"{username} has access key older than 90 days", "Medium"))

        # No tags (Low)
        tags = client.list_user_tags(UserName=username).get("Tags", [])
        if not tags:
            findings.append((f"{username} has no IAM tags", "Low"))

    return findings
