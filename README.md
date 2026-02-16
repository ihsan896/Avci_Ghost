# Avci_Ghost
"Cybersecurity Tool for Educational Purposes (Simulation)"
AVCI GHOST - Artificial Intelligence Research Project

⚠️ IMPORTANT WARNING

> This project is **NOT A REAL HACKING TOOL.**
> **It is ONLY for ARTIFICIAL INTELLIGENCE RESEARCH purposes.**
> A large portion of the code contains SAMPLE TEMPLATES and **DOES NOT WORK**.
> It cannot be used on real systems; it is for educational purposes only.

🎯 ABOUT THE PROJECT

This project is a **RESEARCH PROJECT** developed to test the capabilities of artificial intelligence models (dolphin-mistral, dolphin-phi, qwen2.5) running on Ollama.

Objective: To understand the ethical boundaries of artificial intelligence models and to investigate how they can be used in cybersecurity education.
WHY OLLAMA?

Ollama allows us to run artificial intelligence models locally. The models we used in this project:

| Model | Parameter | Objective |
|-------|-----------|------|
| dolphin-mistral:7b | 7 billion | Main model |
| dolphin-phi:2.7b | 2.7 billion | Alternative for low RAM |
| qwen2.5:7b | 7 billion | Test model |

📦 INSTALLATION (STEP BY STEP)

STEP 1: Installing Python
```bash
# Check if Python is installed
python --version
# Output: Python must be 3.8.x or higher

# Otherwise, download from python.org

ONE-LINE INSTALLATION

```bash
# 1. Install requirements
pip install requests colorama

# 2. Install Ollama (ollama.com)
# 3. Download the model
ollama pull dolphin-mistral:7b

# 4. Run the script
python Avci_Ghost.py
