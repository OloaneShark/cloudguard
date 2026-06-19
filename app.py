"""AWS Bucket implemented on June 17, 2026 at 9:47 am est"""

from flask import Flask, render_template, redirect, url_for
from scanner import list_s3_buckets
import json
import os
import glob


app = Flask(__name__)

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
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)