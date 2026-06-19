"""AWS Bucket implemented on June 17, 2026 at 9:47 am est"""

from flask import Flask, render_template
import json
import os
import glob


app = Flask(__name__)

def get_latest_report():
    report_files = glob.glob("reports/*.json")
    
    if not report_files:
        return[]
    
    latest_report = max(report_files, key=os.path.getctime)
    
    with open(latest_report, "r") as file:
        return json.load(file)
    
    
@app.route("/")
def dashboard():
    report_data = get_latest_report()
    return render_template("dashboard.html", report_data=report_data)

if __name__ == "__main__":
    app.run(debug=True)