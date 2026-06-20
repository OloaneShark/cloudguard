"""AWS Bucket implemented on June 17, 2026 at 9:47 am est"""

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
    report_files = get_report_files()
    history = []
    
    for report_file in report_files:
        with open(report_file, "r") as file:
            data = json.load(file)
            
        history.append({
            "file": os.path.basename(report_file),
            "scan_time": data.get("scan_time"),
            "average_score": data.get("average_score"),
            "total_buckets": data.get("total_buckets")
        })
    
    return history

    
@app.route("/")
def dashboard():
    report_data = get_last_report()
    scan_history = get_scan_history()
    
    return render_template(
        "dashboard.html",
        report_data=report_data,
        scan_history=scan_history
    )
    

@app.route("/scan")
def run_scan():
    list_s3_buckets()
    latest_report = get_last_report()
    save_report_to_database(latest_report)
    return redirect(url_for("dashboard"))


@app.route("/report/<filename>")
def view_report(filename):
    report_path = os.path.join("reports", filename)
    
    with open(report_path, "r") as file:
        report_data = json.load(file)
        
    scan_history = get_scan_history()
    
    return render_template(
        "dashboard.html",
        report_data=report_data,
        scan_history=scan_history
    )


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)