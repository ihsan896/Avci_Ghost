 COMPLETE SETUP GUIDE FOR BEGINNERS

>  BEFORE YOU START:** This guide assumes you know NOTHING about coding. We'll explain EVERY step!

 WHAT YOU NEED (SYSTEM REQUIREMENTS)

- **Computer:** Any Windows/Linux/Mac computer
- **Internet:** Required for downloading
- **RAM:** At least 8GB (recommended)
- **Storage:** At least 10GB free space

---

 STEP 1: CHECK YOUR SYSTEM

 Windows Users:
1. Press `Windows Key + R` on your keyboard
2. Type `cmd` and press Enter (black screen opens)
3. Type this and press Enter:
   ```bash
   python --version
   Mac/Linux Users:
Press Command + Space (Mac) or Ctrl + Alt + T (Linux)

Type terminal and open it

Type this and press Enter:

bash
python3 --version
What you should see: Python 3.8.x or higher

STEP 2: INSTALL PYTHON (If you don't have it)
For Windows:
Go to https://python.org

Click yellow "Download Python" button

Open downloaded file

IMPORTANT: Check "Add Python to PATH" box!

Click "Install Now"

Wait for installation

Restart your computer

For Mac:
Go to https://python.org

Click yellow "Download Python" button

Open downloaded file

Follow installation steps

Done!

For Linux:
bash
sudo apt update
sudo apt install python3 python3-pip
After installation, test it:
Open CMD/Terminal and type:

bash
python --version
 STEP 3: INSTALL REQUIRED LIBRARIES
Open CMD/Terminal and type these commands ONE BY ONE:

bash
# First command (press Enter after each)
pip install requests

# Second command
pip install colorama

# Check if installed
pip list
What is this?

requests = Allows program to connect to internet

colorama = Makes text colorful in terminal

STEP 4: INSTALL OLLAMA
What is Ollama?
Ollama lets you run AI models on YOUR computer (not on cloud).

Installation:
For Windows:

Go to https://ollama.com

Click "Download" button (blue button)

Open OllamaSetup.exe

Follow installation steps

Restart your computer

For Mac:

Go to https://ollama.com

Click "Download" button

Open downloaded file

Drag Ollama to Applications folder

For Linux:

bash
curl -fsSL https://ollama.com/install.sh | sh
Check if Ollama installed:
Open NEW CMD/Terminal and type:

bash
ollama --version
STEP 5: DOWNLOAD AI MODELS
Now we need to download AI models. Open CMD/Terminal and type:

bash
# Main model (requires 8GB RAM)
ollama pull dolphin-mistral:7b
or anyway model
# This will take 5-10 minutes (model is 4GB)
# Wait until you see "success"
If you have low RAM (4-6GB):

bash
# Use smaller model instead
ollama pull dolphin-phi:2.7b
Check downloaded models:

bash
ollama list
STEP 6: CREATE CUSTOM MODEL (Optional)
This step is OPTIONAL. You can skip to STEP 8 if you want.

If you want to create a custom model using our Modelfile:

bash
# Make sure you're in the project folder
cd Desktop/Avci_Ghost  # (or wherever you extracted)

# Create custom model
ollama create avci-ghost -f Modelfile.txt

# Check if created
ollama list
You should see avci-ghost:latest in the list.

STEP 8: RUN THE PROGRAM
Make sure you're in the right folder:
bash
# Windows: Check current folder
cd
dir

# Mac/Linux: Check current folder
pwd
ls
If you're not in Avci_Ghost folder:

bash
cd Desktop/Avci_Ghost
Run the program:
bash
python Avci_Ghost.py
If you get error:

Try python3 Avci_Ghost.py (Mac/Linux)

Or py Avci_Ghost.py (Windows)
