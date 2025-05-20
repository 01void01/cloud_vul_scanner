def scan_ebs_findings(session):
    ec2 = session.client("ec2")
    findings = []

    try:
        volumes = ec2.describe_volumes()["Volumes"]

        for vol in volumes:
            vol_id = vol["VolumeId"]
            state = vol["State"]
            encrypted = vol.get("Encrypted", False)
            snapshot_id = vol.get("SnapshotId")

            # Unattached volume
            if state == "available":
                findings.append((f"EBS volume {vol_id} is unattached", "Medium"))

                # With snapshot
                if snapshot_id:
                    findings.append((f"EBS volume {vol_id} has a snapshot but is not attached", "Low"))

            # Not encrypted
            if not encrypted:
                findings.append((f"EBS volume {vol_id} is not encrypted", "Medium"))

    except Exception as e:
        findings.append((f"Error scanning EBS volumes: {str(e)}", "Low"))

    return findings
