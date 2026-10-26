<h1 align="center">🛡️ Python SIEM & SOAR</h1>

<h3 align="center">
  A Beginner-Friendly Cybersecurity Learning Project
</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Project-Educational-2ea44f?style=for-the-badge" alt="Educational Project">
  <img src="https://img.shields.io/badge/GUI-Tkinter-orange?style=for-the-badge" alt="Tkinter">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License">
</p>

<p align="center">
  A Python-based SIEM & SOAR simulation featuring security log generation,
  basic SSH brute-force detection, simulated automated responses,
  and a desktop dashboard.
</p>

---

> **Note:** This is a small educational project created for learning,
> experimentation, and personal portfolio development. It is not a
> production-ready security solution.
>

 ## 📌 About the Project

**Python SIEM & SOAR** is a small Python project developed to explore the fundamentals of cybersecurity monitoring and automated response.

The application generates simulated security events, analyzes log files for repeated failed SSH login attempts, records suspicious IP addresses, and displays event information through a desktop dashboard.

This project was created to practice Python programming and understand basic SIEM and SOAR concepts in a local simulation environment.

> ⚠️ **Educational Use Only:** This project is intended for learning and experimentation. It is not a production-ready security platform and does not replace professional SIEM or SOAR solutions.

---

## ✨ Features

- 📝 **Security Log Generation** — Generates simulated SSH login events, port scan alerts, and firewall-related events.
- 🔍 **Basic Threat Detection** — Detects IP addresses associated with repeated failed SSH login attempts using a simple threshold rule.
- 🤖 **SOAR Response Simulation** — Records suspicious IP addresses and simulated response actions in local files.
- 📊 **Desktop Dashboard** — Displays security logs, event distribution charts, and recorded IP addresses.
- 📁 **Local Log Storage** — Stores generated security events and response records locally.
- 🧩 **Modular Python Structure** — Separates log generation, detection logic, response handling, and dashboard functionality.

 ---

## 🏗️ Project Structure

```text
Python-SIEM-SOAR/
├── main.py             # Starts and manages application processes
├── log_generator.py    # Generates simulated security logs
├── siem_engine.py      # Analyzes logs and detects suspicious activity
├── soar_actions.py     # Records simulated response actions
├── dashboard.py        # Provides the desktop dashboard and charts
├── requirements.txt    # Lists Python dependencies
├── .gitignore          # Excludes generated and local files
├── LICENSE             # MIT License
└── README.md           # Project documentation
```
---

## 🔄 How It Works

The application follows a simple four-step workflow:

1. **Log Generation:** `log_generator.py` generates simulated security events and writes them to `logs/security.log`.

2. **Threat Detection:** `siem_engine.py` analyzes the log file and checks for repeated failed SSH login attempts. When an IP address reaches the configured threshold, it triggers the response module.

3. **Simulated Response:** `soar_actions.py` records the suspicious IP address in `logs/blocked_ips.txt` and logs the response action in `logs/soar_actions.log`.

4. **Dashboard Visualization:** `dashboard.py` displays security logs, event distribution charts, and recorded IP addresses through a desktop interface.

> **Note:** The SOAR module records simulated response actions in local files. It does not block network traffic through a real firewall.

---

## 🛠️ Technologies Used

- **Python** — Core application logic and process management.
- **Tkinter** — Desktop graphical user interface.
- **Pandas** — Log data processing and analysis.
- **Matplotlib** — Event distribution charts and visualizations.
- **Regular Expressions (`re`)** — Log parsing and IP address extraction.
- **Subprocess** — Starting and managing application processes.

---

## ⚙️ Installation & Usage

### 1. Clone the Repository

    git clone https://github.com/quantum-root/Python-SIEM-SOAR.git
    cd Python-SIEM-SOAR


### 2. Create a Virtual Environment

    python -m venv .venv

Activate the environment.

**Windows (Command Prompt):**

    .venv\Scripts\activate

**Windows (PowerShell):**

    .venv\Scripts\Activate.ps1

**Linux / macOS:**

    source .venv/bin/activate

### 3. Install Dependencies

    python -m pip install -r requirements.txt

### 4. Run the Application

    python main.py

The application starts the log generator, SIEM detection engine, and desktop dashboard.

Generated logs and simulation records are stored locally in the `logs/` directory.

---

## 🎯 Learning Objectives

This project was created to practice and explore:

- Basic SIEM and SOAR concepts.
- Security log generation and parsing.
- Threshold-based detection rules.
- Simulated automated response workflows.
- Desktop application development with Tkinter.
- Data visualization using Matplotlib.
- Modular Python application design.

---

## ⚠️ Scope and Limitations

This is a **small educational project**, not a production-ready security platform.

- It uses generated sample events rather than live production security data.
- Detection is based on a simple threshold rule and is not a comprehensive threat detection system.
- The SOAR component records IP addresses in local files; it does not block network traffic through a real firewall.
- The application does not provide enterprise-grade monitoring, authentication, or incident management.
- It has not been designed or tested for production deployment.

This project is intended for learning, experimentation, and personal portfolio development.

---

## 🔐 Security and Privacy

- Use sample data when demonstrating the application.
- Do not upload passwords, API keys, access tokens, or private security logs.
- Generated logs and local environment files should remain outside the public repository.
- Review modifications carefully before adapting the project for real environments.

---

## 🚀 Future Improvements

Possible improvements for future learning include:

- Configurable detection thresholds and time windows.
- Improved log handling and rotation.
- Unit tests for log parsing and detection rules.
- Additional dashboard filters and analytics.
- Better error handling and process management.
- Configurable detection and response rules.

These are potential future enhancements, not features currently implemented.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

Created as a personal Python and cybersecurity learning project.

Feedback, suggestions, and opportunities to learn are welcome.

---

<p align="center">
  <i>Built with Python 🐍 for learning and experimentation.</i>
</p>
