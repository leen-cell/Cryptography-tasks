

# Cryptography Tasks – HW1

This repository contains three cryptography tasks completed as part of **Homework 1** for the Cryptography course.
Each task focuses on a different classical or modern cryptanalysis technique: XOR keystream attack, DES avalanche analysis, and a Meet-in-the-Middle attack.

The full homework report is included in **`report.pdf`**.

---

## Repository Structure

```
Cryptography-tasks/
│── report.pdf
│
├── task1/
│   ├── task1_keystream_attack.py
│   ├── input.txt
│   ├── xorOutput.txt
│   └── target
│
├── task2/
│   ├── task2_des.py
│   ├── task2_des_avalanche_analysis.py
│   └── task2_run_des.py
│
└── task3/
    └── task3_mitm.py
```

---

#  Task 1 — XOR Keystream Attack

**Goal:** Recover plaintext encrypted with a reused XOR keystream.

### Files:

* `task1_keystream_attack.py` — main attack implementation
* `input.txt` — ciphertext input
* `xorOutput.txt` — decrypted output
* `target` — reference/cipher data

### Summary:

The code performs XOR-based keystream recovery by exploiting repeated keystream usage, allowing reconstruction of the plaintext.

---

#  Task 2 — DES + Avalanche Effect Analysis

**Goal:** Study the avalanche effect in DES and test encryption using custom implementations.

### Files:

* `task..._des.py` — DES core implementation
* `task2_des_avalanche_analysis.py` — flips bits and measures changes in output
* `task2_run_des.py` — runs different DES tests

### Summary:

The task evaluates DES behavior under small input variations and demonstrates how one-bit changes propagate through rounds.

---

#  Task 3 — Meet-in-the-Middle (MITM) Attack

**Goal:** Implement a MITM attack on Double-DES (2DES).

### Files:

* `task3_mitm.py` — complete meet-in-the-middle attack

### Summary:

The script performs the classic MITM attack by precomputing one side of DES and matching intermediate values, reducing complexity from 2⁵⁶ to 2⁵⁶ + 2⁵⁶.

---

# Running the Tasks

### Task 1

```bash
python task1/task1_keystream_attack.py
```

### Task 2

```bash
python task2/task2_run_des.py
python task2/task2_des_avalanche_analysis.py
```

### Task 3

```bash
python task3/task3_mitm.py
```

---

#  Report

All explanations, results, and screenshots are included in:

```
report.pdf
```
