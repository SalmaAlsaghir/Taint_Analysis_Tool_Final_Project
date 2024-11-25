import os
import json
from pathlib import Path
from analyzeDjango import analyze_django_app, save_report

def run_tests():
    test_suite_dir = Path(__file__).parent.parent / 'django_test_suite'
    results = analyze_django_app(str(test_suite_dir))

    output_file = test_suite_dir / 'django_test_results.json'
    save_report(results, output_file)
    print(f"Results saved to {output_file}")

if __name__ == '__main__':
    run_tests()
