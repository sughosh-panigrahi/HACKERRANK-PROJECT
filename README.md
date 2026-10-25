# Deletion Audit Agent

## Overview
A deterministic Python-based deletion audit agent that uses a Union-Find identity graph to track user identifiers across dataset stores, check compliance against retention rules, and verify deletion status.

## Directory Structure
- `code/main.py`: Core audit execution engine.
- `dataset/`: Contains input CSV files (`deletion_requests.csv`, `deletion_rules.csv`, and record stores).
- `output.csv`: Output generated audit reports.

## Setup & Running
1. Place dataset CSV files inside the `dataset/` directory.
2. Run the audit agent:
   ```bash
   python3 code/main.py
   ```
3. To evaluate outputs against a ground truth file:
   ```bash
   python3 code/main.py eval path/to/ground_truth.csv
   ```
