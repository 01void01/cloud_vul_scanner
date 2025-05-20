def scan_open_ports(session):
    ec2 = session.client('ec2')
    results = []

    try:
        security_groups = ec2.describe_security_groups()['SecurityGroups']

        for sg in security_groups:
            group_name = sg['GroupName']
            group_id = sg['GroupId']

            for permission in sg.get('IpPermissions', []):
                from_port = permission.get('FromPort')
                ip_ranges = permission.get('IpRanges', [])

                for ip_range in ip_ranges:
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        if from_port == -1 or from_port is None:
                            port_desc = "all ports"
                        else:
                            port_desc = f"port {from_port}"

                        issue = f"Security group {group_name} (ID: {group_id}) allows {port_desc} from 0.0.0.0/0"
                        severity = "High" if from_port in [22, 3389] else "Medium"
                        results.append((issue, severity))

    except Exception as e:
        results.append((f"Error scanning EC2 security groups: {str(e)}", "Low"))

    return results
