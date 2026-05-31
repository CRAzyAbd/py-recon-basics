# Setup Guide

## Requirements

- Python 3.10 or higher
- pip (comes bundled with Python)
- Git

## Installation

**1. Clone the repo:**

    git clone https://github.com/YOUR_USERNAME/py-recon-basics.git
    cd py-recon-basics

**2. Create a virtual environment:**

    python3 -m venv venv
    source venv/bin/activate

A `(venv)` prefix will appear in your terminal when active.

**3. Install dependencies:**

    pip install -r requirements.txt

**4. Run the tool:**

    python main.py --help

> Full CLI support is added on Day 6. Before that, run individual module files directly.

## Deactivating the Virtual Environment

    deactivate

## Troubleshooting

**`python3: command not found`**
Run: `sudo apt install python3`

**`python3 -m venv` fails with an error**
Run: `sudo apt install python3-venv`
