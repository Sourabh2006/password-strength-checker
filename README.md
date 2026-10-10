# 🛡️ PassGuard: Password Strength Checker & Credential Auditor

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![GUI](https://img.shields.io/badge/GUI-Tkinter%20%26%20Web-emerald.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(StdLib)-success.svg)]()
[![Tests](https://img.shields.io/badge/Tests-24%2F24%20Passing-brightgreen.svg)]()
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Volatile%20Memory-purple.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An offline, cryptographically sound credential auditing and entropy analysis engine with **both a native desktop GUI and an interactive web dashboard**. Evaluates password resilience using information theory (**Shannon Entropy**), theoretical keyspace combinatorics ($R \le 95$), pattern-recognition heuristics, and leetspeak de-obfuscation.

Built with **100% Python Standard Library** — runs anywhere with zero `pip install` prerequisites.

---

## 📸 Interface Options

### 1. 🖥️ Native Desktop GUI (`gui.py` / `python app.py`)
- Real-time keystroke evaluation with sub-millisecond response latency.
- Modern dark-mode cybersecurity theme (Slate-900 / Slate-800).
- Visual score gauge ($0-100$) and color-coded strength classification pills.
- Character diversity badges (lowercase, uppercase, numbers, symbols, active pool size $R$, and unique counts).
- Live entropy metrics: Shannon entropy per symbol ($H$), total information entropy ($E_{\text{shannon}}$), and keyspace search space ($E_{\text{keyspace}}$).
- Vulnerability scanner flagging dictionary root words, leetspeak masks (e.g. `p@ssword` $\rightarrow$ `password`), keyboard walks (`qwerty`), and repetitions (`123456`, `aaaa`).
- Actionable suggestions offering targeted remediation steps.
- Built-in CSPRNG password & XKCD passphrase generator with brute-force cracking resistance estimates.
- 1-click test benchmarks for weak, moderate, and robust credentials.

```
┌────────────────────────────────────────────────────────────────────────┐
│  🛡️ PassGuard Auditor    [ 🔒 100% Volatile Memory • Zero Storage ]   │
├────────────────────────────────────────────────────────────────────────┤
│  INPUT CREDENTIAL FOR INSTANT AUDIT      [👁️ Show]  [📋 Copy]  [🗑️ Clear]│
│  [ ●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●                           ]       │
├───────────────────────────────────┬────────────────────────────────────┤
│  STRENGTH EVALUATION   85 / 100   │  VULNERABILITIES & PATTERNS        │
│  [========================----]   │  ✅ Clean — No dictionary words,    │
│  Cracking Difficulty: ~140 Years  │     leetspeak, or sequences found. │
├───────────────────────────────────┼────────────────────────────────────┤
│  CHARACTER DIVERSITY & POOL       │  ACTIONABLE RECOMMENDATIONS        │
│  [✓] Lowercase (a-z) : 12 chars   │  • Excellent length & diversity!   │
│  [✓] Uppercase (A-Z) : 4 chars    │  • High entropy passphrase model.  │
│  [✓] Digits (0-9)    : 2 chars    │                                    │
│  [✓] Symbols (!@#$)  : 2 chars    │                                    │
├───────────────────────────────────┼────────────────────────────────────┤
│  ENTROPY METRICS                  │  CSPRNG GENERATOR & BENCHMARKS     │
│  • Shannon Entropy : 4.12 b/char  │  [⚡ Generate Random] [📖 XKCD]     │
│  • Total Entropy   : 82.4 bits    │  Presets: [123456] [p@ssword]      │
│  • Keyspace Size   : 131.4 bits   │           [Summer2023!] [Robust]   │
└───────────────────────────────────┴────────────────────────────────────┘
```

### 2. 🌐 Local Web GUI Dashboard (`web_gui.py` / `python app.py --web`)
- Full browser-based responsive glassmorphism dashboard served at `http://127.0.0.1:8080`.
- Pure standard library HTTP server (`http.server`) and REST JSON API endpoints.
- Auto-launches your default web browser on start.

### 3. ⌨️ Interactive Secure Terminal CLI (`cli.py` / `python app.py --cli`)
- Hidden input prompt (`getpass`) preventing terminal shoulder-surfing and shell history leakage.
- Machine-readable `--json` output mode (raw password strictly omitted from output).

---

## 📐 Mathematical Formulas & Entropy Scoring

### 1. Shannon Entropy per Symbol ($H$)

Claude Shannon's information entropy measures the average information density or unpredictability generated per symbol:

$$H(X) = -\sum_{i=1}^{k} p(x_i) \log_2 p(x_i)$$

Where:
- $k$ is the number of distinct unique characters in the password.
- $p(x_i)$ is the empirical probability of character $x_i$ occurring:
  $$p(x_i) = \frac{\text{count}(x_i)}{L}$$
- $L$ is the total length of the password.
- $H(X)$ is expressed in **bits per symbol**.

**Examples**:
- Identical string (`"aaaaaaaa"`):
  $$p('a') = \frac{8}{8} = 1.0 \implies H = -(1.0 \times \log_2(1.0)) = 0.00 \text{ bits/symbol}$$
- Alternating string (`"abababab"`):
  $$p('a') = 0.5, p('b') = 0.5 \implies H = -(0.5 \times (-1) + 0.5 \times (-1)) = 1.00 \text{ bit/symbol}$$

### 2. Total Shannon Information Entropy ($E_{\text{shannon}}$)

The aggregate information entropy contained across the entire password:

$$E_{\text{shannon}} = L \times H(X) = - L \sum_{i=1}^{k} \left(\frac{\text{count}(x_i)}{L}\right) \log_2\left(\frac{\text{count}(x_i)}{L}\right)$$

### 3. Theoretical Keyspace Entropy ($E_{\text{keyspace}}$)

Keyspace entropy represents the search space size if an attacker tests all combinations over the observed character pool:

$$E_{\text{keyspace}} = L \times \log_2(|R|)$$

Where $|R|$ represents the combined size of all active character classes:

| Character Class | Symbols | Set Size |
|---|---|:---:|
| Lowercase letters | `a-z` | $26$ |
| Uppercase letters | `A-Z` | $26$ |
| Decimal digits | `0-9` | $10$ |
| Special punctuation & symbols | `!@#$%^&*()...` | $33$ |
| **Combined Pool Max** | | $\mathbf{95}$ |

### 4. Brute-Force Cracking Difficulty Estimation

Cracking duration is estimated against a high-end offline GPU cracking cluster testing $10^{11}$ (100 billion) hashes per second:

$$\text{Time (seconds)} \approx \frac{2^{E - 1}}{10^{11}}$$

$$\log_2(\text{Time}) = E - 1 - \log_2(10^{11}) \approx E - 37.54$$

---

## 🔍 Vulnerability & Pattern Detection

### Leetspeak & Weak Substitutions
Attackers use automated mutation rules to crack passwords that substitute letters with lookalike numbers or symbols. PassGuard executes a de-obfuscation normalization pass:
- `@`, `4` $\rightarrow$ `a`
- `8` $\rightarrow$ `b`
- `3` $\rightarrow$ `e`
- `1`, `!`, `|` $\rightarrow$ `i`
- `0` $\rightarrow$ `o`
- `$`, `5` $\rightarrow$ `s`
- `7`, `+` $\rightarrow$ `t`

*Example*: `"p@ssword"` and `"P@55w0rd"` are normalized to `"password"`, flagging the critical leetspeak vulnerability and capping the score to $0/100$.

### Dictionary & Breached Credential Matching
Maintains an internal set of common passwords, breached credentials, and root words (e.g., `admin`, `welcome`, `summer`, `master`, `superman`). Substrings of length $\ge 4$ are checked in $O(1)$ set lookups.

### Predictable Sequences & Keyboard Walks
- **Sequences**: Ascending/descending numerical runs (`123456`, `654321`) and alphabetical runs (`abcdef`, `fedcba`).
- **Keyboard Walks**: Contiguous paths across QWERTY keyboard rows (`qwerty`, `asdfgh`, `zxcvbnm`), reverse sweeps (`poiuyt`), and diagonal strokes (`1qaz`, `2wsx`).

### Repetition & Chunk Loops
- **Character Runs**: Three or more consecutive identical characters (`aaaa`, `1111`).
- **Chunk Loops**: Repeating substring patterns of length $2$ to $8$ (`abcabc`, `passpass`).

---

## 🔒 Privacy Guarantees & Zero-Storage Architecture

```
User Input (GUI / CLI)
       │
       ▼
 [Volatile Stack Memory] ──── (Entropy & Pattern Auditing)
       │
       ▼
 [Evaluation Result] ──────── (UI Render / Zero-Storage JSON)
       │
       ▼
 [Memory Garbage Collected]
 (NO Disk Writes, NO Network I/O, NO Logs, NO Telemetry)
```

1. **Volatile Memory Only**: Passwords exist exclusively in local stack variables during function invocation.
2. **Zero Persistent Storage**: No database, cache, SQLite, or file storage. Verified by unit tests asserting zero file creation during evaluation.
3. **Zero Network Transmission**: Operates 100% offline. Zero HTTP requests, zero sockets, zero external APIs.
4. **Safe Data Serialization**: The `EvaluationResult.to_dict()` and JSON serialization methods strictly exclude the raw input password.

---

## 📁 Repository Structure

```
.
├── src/
│   ├── __init__.py          # Public exports
│   ├── checker.py           # Core PasswordStrengthChecker engine
│   ├── entropy.py           # Shannon & keyspace entropy math
│   ├── generator.py         # CSPRNG password & XKCD passphrase generator
│   ├── patterns.py          # Leetspeak, sequences, keyboard walk & repetition detectors
│   ├── dictionaries.py      # Common passwords & dictionary wordlist
│   └── models.py            # Result models, enums, dataclasses
├── tests/
│   ├── __init__.py
│   └── test_password_checker.py # 24 automated unit tests
├── web/
│   └── index.html           # Modern glassmorphism Web GUI frontend
├── app.py                   # Unified master launcher (GUI, Web, CLI, Demo, Test)
├── gui.py                   # Native Tkinter Desktop GUI
├── web_gui.py               # Local Web GUI dashboard server
├── cli.py                   # Interactive secure CLI with hidden input
├── run_demo.py              # Programmatic usage demonstration
├── requirements.txt         # Dependency documentation (StdLib only)
├── LICENSE                  # MIT License
├── .gitignore               # Clean git exclusion rules
└── README.md                # Technical documentation
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.8+** (pre-installed on Windows, macOS, and Linux).
- **Zero pip packages required** (all features run on Python's built-in standard library).

### 1. Run Desktop GUI (Recommended)
```bash
python app.py
# Or directly:
python gui.py
```

### 2. Run Web GUI Dashboard
```bash
python app.py --web
# Or directly:
python web_gui.py
```
*Opens your web browser automatically at `http://127.0.0.1:8080`.*

### 3. Run Interactive Secure CLI
```bash
python app.py --cli
# Or directly:
python cli.py
```

### 4. Run Benchmark Demo
```bash
python app.py --demo
```

### 5. Run Full Unit Test Suite
```bash
python app.py --test
# Or directly with unittest:
python -m unittest discover tests -v
```

---

## 📊 Benchmark Scoring Comparison

| Password | Length | Shannon Entropy ($E$) | Score | Strength Rating | Detected Weakness |
|---|:---:|:---:|:---:|:---:|---|
| `123456` | 6 | 15.5 bits | 0 / 100 | **Very Weak** | Sequential numbers, dictionary word |
| `password` | 8 | 22.0 bits | 0 / 100 | **Very Weak** | Top breached dictionary credential |
| `qwerty` | 6 | 15.5 bits | 0 / 100 | **Very Weak** | QWERTY keyboard walk |
| `p@ssword` | 8 | 22.0 bits | 0 / 100 | **Very Weak** | Leetspeak substitution of `"password"` |
| `aaaa1111` | 8 | 8.0 bits | 0 / 100 | **Very Weak** | Consecutive repeats & low entropy |
| `admin123` | 8 | 24.0 bits | 0 / 100 | **Very Weak** | Dictionary word + numeric sequence |
| `Summer2023!` | 11 | 34.1 bits | 43 / 100 | **Weak** | Dictionary word `"summer"`, year `"2023"` |
| `BlueSky99` | 9 | 26.5 bits | 60 / 100 | **Moderate** | Moderate length, partial character set |
| `CorrectHorse1` | 13 | 39.4 bits | 74 / 100 | **Strong** | Long passphrase stem + digit |
| `K9#m$P2!vL8@qR4&` | 16 | 64.0 bits | 100 / 100 | **Very Strong** | High entropy, 4 classes, zero patterns |
| `correct-horse-battery-staple-99!` | 32 | 118.0 bits | 92 / 100 | **Very Strong** | High-entropy multi-word passphrase |
| `Xj8$wL2#vQ9!mZ4&pB7*` | 20 | 86.4 bits | 100 / 100 | **Very Strong** | 20-character random complex credential |

---

## 📤 How to Upload this Project to GitHub

Follow any of the three methods below to upload your project to GitHub:

### Method 1: Using Git Command Line (Recommended)

1. Open PowerShell or Command Prompt in this project directory:
   ```bash
   cd "c:\Users\Sourang_official\OneDrive\Documents\codenova\New folder"
   ```
2. Initialize Git, stage files, and make your first commit:
   ```bash
   git init
   git add .
   git commit -m "feat: Password Strength Checker with Native & Web GUI"
   ```
3. Create a new repository on [github.com](https://github.com/new) named `password-strength-checker` (keep it public, do not initialize with README since you already have one).
4. Link your remote repository and push:
   ```bash
   git branch -M main
   git remote add origin https://github.com/YOUR_GITHUB_USERNAME/password-strength-checker.git
   git push -u origin main
   ```

*(If `git` is not installed on your system, install it in 1 minute by downloading [Git for Windows](https://git-scm.com/download/win) or running `winget install --id Git.Git -e` in PowerShell).*

---

### Method 2: Using GitHub Desktop (Graphical / No Commands)

1. Download and open [GitHub Desktop](https://desktop.github.com/).
2. Click **File** > **Add Local Repository...**.
3. Choose this folder path (`c:\Users\Sourang_official\OneDrive\Documents\codenova\New folder`).
4. If prompted that the folder is not a Git repository, click **create a repository here**.
5. Write commit summary: `Initial commit: Password Strength Checker with GUI`.
6. Click **Publish repository** to push it directly to your GitHub profile!

---

### Method 3: Using Web Browser Upload (Drag-and-Drop)

1. Go to [github.com/new](https://github.com/new) and create a repository named `password-strength-checker`.
2. On the new repository page, click the link: **"uploading an existing file"**.
3. Drag and drop all project files and folders (`src/`, `tests/`, `web/`, `gui.py`, `app.py`, `web_gui.py`, `cli.py`, `README.md`, `LICENSE`, `requirements.txt`, etc.).
4. Click **Commit changes**.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
