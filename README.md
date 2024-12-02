# Taint Analysis Tool for React and Django Applications

This project implements a **taint analysis tool** that detects security vulnerabilities, particularly those related to untrusted data flow, in modern web applications. The tool uses **static analysis** methods to identify common vulnerabilities like **SQL Injection**, **XSS (Cross-Site Scripting)**, and **Command Injection**. It works with both **React (frontend)** and **Django (backend)** frameworks.

The tool tracks the flow of untrusted user input through the application and detects potential points where data is processed unsafely. It is designed to be integrated into a standard development workflow, allowing developers to automatically scan their code for security flaws.

## Key Features
- **Static Analysis**: Leverages abstract syntax tree (AST) traversal, taint propagation, and sanitization detection to analyze code.
- **Cross-Framework Compatibility**: Supports both React (JavaScript) and Django (Python) applications.
- **Vulnerability Detection**: Identifies common vulnerabilities such as SQL Injection, XSS, and Command Injection.
- **Integration with Development Workflow**: Can be easily integrated into a CI/CD pipeline to automatically check for vulnerabilities.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Directory Structure](#directory-structure)
- [Vulnerabilities Detected](#vulnerabilities-detected)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SalmaAlsaghir/Taint_Analysis_Tool_Final_Project.git
   cd Taint_Analysis_Tool_Final_Project
   ```

2. **Install Dependencies**:
   The tool uses Python for backend analysis (Django) and JavaScript for frontend analysis (React). Ensure you have `npm` and `pip` installed.

   - For the **React application**:
     ```bash
     cd my-react-app
     npm install
     ```

   - For the **Django application**:
     ```bash
     cd my-django-project
     ```

3. **Install Taint Analysis Tool Dependencies**:
   The tool requires Python and some additional packages for static analysis.

   ```bash
   cd tool
   ```

## Usage

1. **Running the React Application Analysis**:
   After installing the dependencies, you can run the tool on the React application code using Node.js:

   ```bash
   node analyzeReact.js --path ../my-react-app
   ```

2. **Running the Django Application Analysis**:
   Similarly, you can analyze the Django application by running the following:

   ```bash
   python analyzeDjango.py --path ../my-django-project
   ```

3. **Testing the Tool**:
   After running the analysis scripts, check the output logs to see the identified vulnerabilities. The tool flags vulnerabilities in the code, such as:
   - **Unsafe use of `eval()`**
   - **Direct DOM manipulation (XSS risks)**
   - **SQL injection points**
   - **Improper input sanitization**

## Directory Structure

```
Taint_Analysis_Tool_Final_Project/
│
├── my-react-app/            # React frontend code
├── my-django-project/       # Django backend code
│
├── react-test-suite/        # Test cases for React
├── django-test-suite/       # Test cases for Django
│
├── tool/                    # Taint analysis tool scripts
│   ├── analyzeReact.js      # React analysis script (Node.js)
│   ├── analyzeDjango.py     # Django analysis script (Python)
│   ├── run_react_app_analysis.js  # React app analysis helper (Node.js)
│   ├── run_django_app_analysis.py  # Django app analysis helper (Python)
│   ├── run_react_tests.js   # React test suite execution (Node.js)
│   ├── run_django_tests.py  # Django test suite execution (Python)
│        
├── README.md                # This file
```

### Files in the `tool/` folder:
- **`analyzeReact.js`**: Analyzes the React application code for security vulnerabilities like XSS and SQL Injection.
- **`analyzeDjango.py`**: Analyzes the Django application code for vulnerabilities like SQL Injection and Command Injection.

- **`run_react_app_analysis.js`**: Helper script that facilitates the analysis of the React application code by running the `analyzeReact.js` script on the specified React project directory.
- **`run_django_app_analysis.py`**: Helper script that facilitates the analysis of the Django application code by running the `analyzeDjango.py` script on the specified Django project directory.

- **`run_react_tests.js`**: Executes the React test suite, running tests designed to detect security flaws in the React application.
- **`run_django_tests.py`**: Executes the Django test suite, running tests designed to detect security flaws in the Django application.

These helper scripts make it easier to run the analysis and tests without directly interacting with the core analysis scripts.

## Vulnerabilities Detected

The tool can detect several types of vulnerabilities in both React and Django applications:

- **SQL Injection**: The tool identifies unsafe data flows that could lead to SQL injection, such as direct concatenation of user input into SQL queries.
- **XSS (Cross-Site Scripting)**: It detects where unescaped user input is inserted into HTML or JavaScript code, potentially leading to XSS vulnerabilities.
- **Command Injection**: Identifies cases where untrusted input is passed to system commands, which could allow arbitrary command execution.
- **Insecure Deserialization**: Detects untrusted deserialization of objects, which may lead to code execution or data manipulation.

## Contributing

Contributions to this project are welcome. If you'd like to improve the taint analysis tool or add more vulnerability detection features, feel free to fork the repository and submit a pull request.

### Steps to Contribute:
1. Fork the repository.
2. Clone your fork to your local machine:
   ```bash
   git clone https://github.com/SalmaAlsaghir/Taint_Analysis_Tool_Final_Project.git
   ```
3. Create a new branch:
   ```bash
   git checkout -b feature/your-feature
   ```
4. Make your changes and commit them:
   ```bash
   git commit -m "Description of changes"
   ```
5. Push to your fork and submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Like this project?** Star the repository on GitHub and feel free to open an issue if you encounter bugs or have feature suggestions.

```
