from flask import Blueprint, render_template, request, flash, redirect, url_for, session, make_response
from flask_login import login_required, current_user
from app.scanners import s3_scanner, ec2_scanner, iam_scanner, rds_scanner, ebs_scanner
import boto3
from botocore.exceptions import NoCredentialsError
from xhtml2pdf import pisa
import io

routes_bp = Blueprint('routes', __name__)

def create_boto_session(access_key, secret_key, region):
    """Create a boto3 session with provided credentials"""
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

def add_severity(data, severity, source):
    """Helper function to add severity and source to scan results"""
    return [{"issue": item, "severity": severity, "source": source} for item in data]

@routes_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page for the vulnerability scanner"""
    return render_template('dashboard.html', user=current_user)

@routes_bp.route('/scan', methods=['POST'])
@login_required
def scan():
    """Handle vulnerability scanning requests"""
    access_key = request.form.get('access_key', "").strip()
    secret_key = request.form.get('secret_key', "").strip()
    region = request.form.get('region', "").strip()
    scan_type = request.form.get('scan_type')

    # Validate required fields
    if not access_key or not secret_key or not region or not scan_type:
        flash("All fields are required.", "danger")
        return redirect(url_for('routes.dashboard'))

    try:
        # Create AWS session
        session_obj = create_boto_session(access_key, secret_key, region)

        # Initialize results
        s3_results = ec2_results = iam_results = rds_results = ebs_results = []
        all_results = []

        # Perform scans based on selected type
        if scan_type == "s3":
            s3_raw = s3_scanner.scan_s3_findings(session_obj)
            s3_results = [issue for issue, _ in s3_raw]
            all_results += [{"issue": issue, "severity": sev, "source": "S3"} for issue, sev in s3_raw]
            flash("S3 Scan Completed!", "success")

        elif scan_type == "ec2":
            ec2_raw = ec2_scanner.scan_open_ports(session_obj)
            ec2_results = [issue for issue, _ in ec2_raw]
            all_results += [{"issue": issue, "severity": sev, "source": "EC2"} for issue, sev in ec2_raw]
            flash("EC2 Scan Completed!", "success")

        elif scan_type == "iam":
            iam_raw = iam_scanner.scan_iam_findings(session_obj)
            iam_results = [issue for issue, _ in iam_raw]
            all_results += [{"issue": issue, "severity": sev, "source": "IAM"} for issue, sev in iam_raw]
            flash("IAM Scan Completed!", "success")

        elif scan_type == "rds":
            rds_raw = rds_scanner.scan_public_rds(session_obj)
            rds_results = [issue for issue, _ in rds_raw]
            all_results += [{"issue": issue, "severity": sev, "source": "RDS"} for issue, sev in rds_raw]
            flash("RDS Scan Completed!", "success")

        elif scan_type == "ebs":
            ebs_raw = ebs_scanner.scan_ebs_findings(session_obj)
            ebs_results = [issue for issue, _ in ebs_raw]
            all_results += [{"issue": issue, "severity": sev, "source": "EBS"} for issue, sev in ebs_raw]
            flash("EBS Scan Completed!", "success")

        elif scan_type == "all":
            # Perform all scans
            s3_results = s3_scanner.scan_s3_findings(session_obj)
            ec2_results = ec2_scanner.scan_open_ports(session_obj)
            iam_results = iam_scanner.scan_iam_findings(session_obj)
            rds_results = rds_scanner.scan_public_rds(session_obj)
            ebs_results = ebs_scanner.scan_ebs_findings(session_obj)

            # Combine all results
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

        # Store results in session for PDF export
        session['all_results'] = all_results
        session['last_scan_user'] = current_user.username

        return render_template('dashboard.html',
                               user=current_user,
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

@routes_bp.route('/export-pdf')
@login_required
def export_pdf():
    """Export scan results to PDF"""
    if not session.get('all_results'):
        flash("No scan results to export.", "warning")
        return redirect(url_for('routes.dashboard'))

    # Check if current user performed the scan
    if session.get('last_scan_user') != current_user.username:
        flash("You can only export your own scan results.", "warning")
        return redirect(url_for('routes.dashboard'))

    try:
        # Render the PDF template with results
        rendered = render_template('pdf_template.html', 
                                   all_results=session['all_results'],
                                   user=current_user)
        
        # Create PDF
        pdf = io.BytesIO()
        pisa_status = pisa.CreatePDF(rendered, dest=pdf)

        if pisa_status.err:
            flash("Error creating PDF report.", "danger")
            return redirect(url_for('routes.dashboard'))

        # Prepare response
        pdf.seek(0)
        response = make_response(pdf.read())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=vulnerability_scan_results.pdf'
        
        return response

    except Exception as e:
        flash(f"Error generating PDF: {str(e)}", "danger")
        return redirect(url_for('routes.dashboard'))

