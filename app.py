"""
AWS Bucket implemented on June 17, 2026 at 9:47 am est
Added CloudTrail security validation and remediation checks on  June 20, 2026 at 2:52 pm est
Deployed CloudGuard to AWS EC2 with Docker and PostgreSQL on June 21, 2026 at 5:19 pm est
"""

from dotenv import load_dotenv
from models import db, Scan, BucketResult, Finding
from flask import Flask, render_template, redirect, url_for
from scanner import list_s3_buckets
import json
import os
import glob

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


def save_report_to_database(report_data):
    existing_scan = Scan.query.filter_by(
        scan_time=report_data["scan_time"]
    ).first()
    
    if existing_scan:
        print("Scan already saved to database")
        return
    
    new_scan = Scan(
        scan_time=report_data["scan_time"],
        total_buckets=report_data["total_buckets"],
        average_score=report_data["average_score"]
    )
    
    db.session.add(new_scan)
    db.session.commit()
    
    for bucket in report_data["buckets"]:
        
        new_bucket = BucketResult(
            scan_id=new_scan.id,
            bucket_name=bucket["bucket_name"],
            security_score=bucket["security_score"]
        )
        
        db.session.add(new_bucket)
        db.session.flush()
        
        for finding in bucket["findings"]:
            if finding.startswith("PASS"):
                severity = "PASS"
            elif finding.startswith("WARNING"):
                severity = "WARNING"
            elif finding.startswith("CRITICAL"):
                severity = "CRITICAL"
            else:
                severity = "INFO"
                
            new_finding = Finding(
                bucket_result_id=new_bucket.id,
                severity=severity,
                message=finding
            )
            
            db.session.add(new_finding)
            
    db.session.commit()
    
    print("Scan saved to database")


def get_report_files():
    report_files = glob.glob("reports/*.json")
    return sorted(report_files, key=os.path.getctime, reverse=True)
    

def get_last_report():
    report_files = get_report_files()
    
    if not report_files:
        return{}
    
    latest_report = report_files[0]
    
    with open(latest_report, "r") as file:
        return json.load(file)
    

def get_scan_history():
    scans = Scan.query.order_by(Scan.id.desc()).all()
    
    history = []
    
    for scan in scans:   
        history.append({
            "id": scan.id,
            "scan_time": scan.scan_time,
            "average_score": scan.average_score,
            "total_buckets": scan.total_buckets
        })
    
    return history

    
@app.route("/")
def dashboard():
    latest_scan = Scan.query.order_by(Scan.id.desc()).first()
    
    if not latest_scan:
        return render_template(
            "dashboard.html",
            report_data = {
                "scan_time": "No scans yet",
                "total_buckets": 0,
                "average_score": 0,
                "buckets": []
            },
            scan_history=[],
            severity_counts= {
                "PASS": 0,
                "WARNING": 0,
                "CRITICAL": 0,
                "INFO": 0
            },
            score_trend=[]
        )
        
    report_data = {
        "scan_time": latest_scan.scan_time,
        "total_buckets": latest_scan.total_buckets,
        "average_score": latest_scan.average_score,
        "buckets": []
    }
    
    severity_counts = {
        "PASS": 0,
        "WARNING": 0,
        "CRITICAL": 0,
        "INFO": 0
    }
    
    for bucket in latest_scan.bucket_results:
        bucket_data = {
            "bucket_name": bucket.bucket_name,
            "security_score": bucket.security_score,
            "findings": [
                finding.message for finding in bucket.findings
            ]
        }
        
        report_data["buckets"].append(bucket_data)
        
    for bucket in report_data["buckets"]:
        for finding in bucket["findings"]:
            if finding.startswith("PASS"):
                severity_counts["PASS"] += 1
            elif finding.startswith("WARNING"):
                severity_counts["WARNING"] += 1
            elif finding.startswith("CRITICAL"):
                severity_counts["CRITICAL"] += 1
            elif finding.startswith("INFO"):
                severity_counts["INFO"] += 1
        
    scan_history = get_scan_history()
    
    trend_data = Scan.query.order_by(Scan.id.asc()).all()
    
    score_trend = [
        {
            "scan_time": scan.scan_time,
            "average_score": scan.average_score
        }
        for scan in trend_data
    ]
    
    return render_template(
        "dashboard.html",
        report_data=report_data,
        scan_history=scan_history,
        severity_counts=severity_counts,
        score_trend=score_trend
    )
    

@app.route("/scan")
def run_scan():
    list_s3_buckets()
    latest_report = get_last_report()
    save_report_to_database(latest_report)
    return redirect(url_for("dashboard"))


@app.route("/report/<int:scan_id>")
def view_report(scan_id):
    selected_scan = Scan.query.get_or_404(scan_id)
    
    report_data = {
        "scan_time": selected_scan.scan_time,
        "total_buckets": selected_scan.total_buckets,
        "average_score": selected_scan.average_score,
        "buckets": []
    }
    
    severity_counts = {
        "PASS": 0,
        "WARNING": 0,
        "CRITICAL": 0,
        "INFO": 0
    }
    
    for bucket in selected_scan.bucket_results:
        bucket_data = {
            "bucket_name": bucket.bucket_name,
            "security_score": bucket.security_score,
            "findings": [
                finding.message for finding in bucket.findings
            ]
        }
        
        report_data["buckets"].append(bucket_data)
        
    for bucket in report_data["buckets"]:
        for finding in bucket["findings"]:
            if finding.startswith("PASS"):
                severity_counts["PASS"] += 1
            elif finding.startswith("WARNING"):
                severity_counts["WARNING"] += 1
            elif finding.startswith("CRITICAL"):
                severity_counts["CRITICAL"] += 1
            elif finding.startswith("INFO"):
                severity_counts["INFO"] += 1
        
    scan_history = get_scan_history()
    
    trend_data = Scan.query.order_by(Scan.id.asc()).all()

    score_trend = [
        {
            "scan_time": scan.scan_time,
            "average_score": scan.average_score
        }
        for scan in trend_data
    ]
    
    return render_template(
        "dashboard.html",
        report_data=report_data,
        scan_history=scan_history,
        severity_counts=severity_counts,
        score_trend=score_trend
    )


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)