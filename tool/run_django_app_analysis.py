import os
import json
from pathlib import Path
from analyzeDjango import analyze_django_app, save_report

def run_app_analysis():
    app_dir = Path(__file__).parent.parent / 'my_django_project'
    results = analyze_django_app(str(app_dir))

    output_file = app_dir / 'django_app_security_report.json'
    save_report(results, output_file)
    print(f"Results saved to {output_file}")

if __name__ == '__main__':
    run_app_analysis()
