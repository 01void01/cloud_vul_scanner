def scan_public_rds(session):
    client = session.client("rds")
    findings = []

    try:
        instances = client.describe_db_instances()["DBInstances"]

        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            is_public = db.get("PubliclyAccessible", False)
            is_encrypted = db.get("StorageEncrypted", False)

            if is_public:
                findings.append((f"{db_id} is publicly accessible",  "Critical"))

            if not is_encrypted:
                findings.append((f"{db_id} is not encrypted at rest", "Medium"))

    except Exception as e:
        findings.append((f"Error scanning RDS: {str(e)}", "Low"))

    return findings
