def scan_s3_findings(session):
    import json
    s3 = session.client('s3')
    findings = []

    try:
        buckets = s3.list_buckets().get('Buckets', [])

        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False

            # Check ACLs for public access
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl['Grants']:
                    if 'AllUsers' in grant['Grantee'].get('URI', ''):
                        is_public = True
                        break
            except Exception:
                pass

            # Check bucket policy for public access
            try:
                policy_response = s3.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(policy_response['Policy'])
                for statement in policy.get('Statement', []):
                    if statement.get('Effect') == 'Allow' and statement.get('Principal') == "*":
                        is_public = True
                        break
            except s3.exceptions.from_code("NoSuchBucketPolicy"):
                pass
            except Exception:
                pass

            # Add finding if public
            if is_public:
                findings.append((f"S3 bucket {bucket_name} is publicly accessible", "High"))

            # Check for encryption
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except s3.exceptions.ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    findings.append((f"S3 bucket {bucket_name} has no encryption enabled", "Medium"))
            except Exception:
                pass

            # Check for logging
            try:
                logging = s3.get_bucket_logging(Bucket=bucket_name)
                if not logging.get("LoggingEnabled"):
                    findings.append((f"S3 bucket {bucket_name} has logging disabled", "Low"))
            except Exception:
                pass

    except Exception as e:
        findings.append((f"Error scanning S3: {str(e)}", "Low"))

    return findings
