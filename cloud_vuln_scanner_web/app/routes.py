from flask import Blueprint, render_template, request, flash, redirect, url_for
from app.scanners import s3_scanner, ec2_scanner, iam_scanner, rds_scanner, ebs_scanner
import boto3
from botocore.exceptions import NoCredentialsError


routes_bp = Blueprint('routes', __name__)

@routes_bp.route('/')
def dashboard():
    return render_template('dashboard.html')

def create_boto_session(access_key, secret_key, region):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

# ✅ Utility function to tag findings with severity + source
def add_severity(data, severity, source):
    return [{"issue": item, "severity": severity, "source": source} for item in data]

@routes_bp.route('/scan', methods=['POST'])
def scan():
    access_key = request.form.get('access_key')
    secret_key = request.form.get('secret_key')
    region = request.form.get('region')
    scan_type = request.form.get('scan_type')

    if not access_key or not secret_key or not region or not scan_type:
        flash("All fields are required.", "danger")
        return redirect(url_for('routes.dashboard'))

    try:
        session = create_boto_session(access_key, secret_key, region)

        s3_results = ec2_results = iam_results = rds_results = ebs_results = []
        all_results = []

        if scan_type == "s3":
            s3_raw = s3_scanner.scan_s3_findings(session)
            s3_results = [issue for issue, _ in s3_raw]
            all_results += [{"issue": issue, "severity": sev, "source": "S3"} for issue, sev in s3_raw]
            flash("S3 Scan Completed!", "success")

        elif scan_type == "ec2":
            ec2_raw = ec2_scanner.scan_open_ports(session)
            ec2_results = [issue for issue, _ in ec2_raw]
            all_results += [{"issue": issue, "severity": sev, "source": "EC2"} for issue, sev in ec2_raw]
            flash("EC2 Scan Completed!", "success")

        elif scan_type == "iam":
            iam_raw = iam_scanner.scan_iam_findings(session)
            iam_results = [issue for issue, _ in iam_raw]
            all_results += [{"issue": issue, "severity": sev, "source": "IAM"} for issue, sev in iam_raw]
            flash("IAM Scan Completed!", "success")


        elif scan_type == "rds":
            rds_raw = rds_scanner.scan_public_rds(session)
            rds_results = [issue for issue, _ in rds_raw]
            all_results += [{"issue": issue, "severity": sev, "source": "RDS"} for issue, sev in rds_raw]
            flash("RDS Scan Completed!", "success")

        elif scan_type == "ebs":
            ebs_raw = ebs_scanner.scan_ebs_findings(session)
            ebs_results = [issue for issue, _ in ebs_raw]
            all_results += [{"issue": issue, "severity": sev, "source": "EBS"} for issue, sev in ebs_raw]
            flash("EBS Scan Completed!", "success")

        elif scan_type == "all":
            s3_results = s3_scanner.scan_s3_findings(session)
            ec2_results = ec2_scanner.scan_open_ports(session)
            iam_results = iam_scanner.scan_iam_findings(session)
            rds_results = rds_scanner.scan_public_rds(session)
            ebs_results = ebs_scanner.scan_ebs_findings(session)

            all_results = []

            for source, results in [
                ("S3", s3_results),
                ("EC2", ec2_results),
                ("IAM", iam_results),
                ("RDS", rds_results),
                ("EBS", ebs_results)
            ]:
                for issue, severity in results:
                    all_results.append({
                        "issue": issue,
                        "severity": severity,
                        "source": source
                    })
            flash("✅ Full Scan Completed!", "success")

        else:
            flash("Invalid scan type selected.", "danger")
            return redirect(url_for('routes.dashboard'))

        return render_template('dashboard.html',
                               s3_results=s3_results,
                               ec2_results=ec2_results,
                               iam_results=iam_results,
                               rds_results=rds_results,
                               ebs_results=ebs_results,
                               all_results=all_results)

    except NoCredentialsError:
        flash("Invalid AWS credentials.", "danger")
        return redirect(url_for('routes.dashboard'))
    except Exception as e:
        flash(f"Unexpected error: {str(e)}", "danger")
        return redirect(url_for('routes.dashboard'))

