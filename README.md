# TrustGuard - Password Strength Tester

A professional, OWASP-informed password strength testing web application with a modern cybersecurity-themed interface and real-time scoring feedback.

## Project Description

TrustGuard helps users create safer passwords by combining clear UX with practical security evaluation rules. It analyzes password quality in real time, detects risky patterns, and provides actionable guidance.

## Features

- Real-time password strength evaluation (0-100)
- Strength levels: **Weak**, **Medium**, **Strong**
- Animated strength meter (red -> yellow -> green)
- Dynamic security feedback messages
- OWASP-inspired checks:
  - Length thresholds (8, 10, 12, 16+)
  - Uppercase, lowercase, numbers, special characters
  - Common password detection
  - Repeated character pattern detection
  - Sequential pattern detection
  - Username inclusion check (user-related input)
  - Passphrase encouragement
- Entropy estimation (bits)
- Show/Hide password toggle
- Strong password generator
- Copy-to-clipboard support

## Technologies Used

- HTML5
- CSS3
- Vanilla JavaScript (ES6)

## How to Run the Project

1. Clone or download the repository.
2. Open `/home/runner/work/TrustGuard/TrustGuard/index.html` in your browser.
3. Type a password and observe the real-time score and guidance.

## OWASP Compliance Explanation

This project follows OWASP-aligned password guidance by:

- Encouraging sufficient password length and complexity
- Discouraging predictable/common passwords and simple patterns
- Penalizing identity-related password content (username inclusion)
- Promoting passphrase-style passwords for stronger memorability + entropy
- Delivering user-friendly feedback to improve password behavior

## Password Security Concepts

### 1) Entropy and Unpredictability
Stronger passwords have higher entropy, meaning they are harder to guess or brute-force. Entropy increases with both character pool diversity and total length.

### 2) Pattern Weaknesses
Attackers exploit known weak patterns such as:
- Dictionary/common passwords
- Repeating characters
- Sequential strings (e.g., `abcd`, `1234`)

### 3) User-Related Data Risk
Including personal identifiers like usernames reduces password security because that information is often public or easy to infer.

### 4) Passphrases
Long, memorable passphrases can provide strong security while being easier for users to remember compared to short random strings.

## Functional Flow of the System

1. User enters username and password.
2. Input event triggers evaluator logic.
3. Scoring engine computes:
   - Positive points (length + diversity + passphrase bonus)
   - Negative points (common/repetitive/sequential/user-related patterns)
4. Engine normalizes score (0-100) and maps it to strength label.
5. UI updates meter, score, label, entropy value, and recommendations in real time.
6. Optional actions:
   - Generate strong password
   - Toggle visibility
   - Copy to clipboard

## Overview of Existing Solutions

Modern password checkers typically combine:
- Rule-based evaluation (easy to explain, fast)
- Breach/common-password checks (high practical value)
- Entropy or probabilistic scoring (risk estimation)

TrustGuard adopts a practical rule-based + entropy approach suitable for front-end deployment while keeping logic transparent for users.

## High-Level Design (Components + Data Flow)

### Components
- `index.html`: UI structure and controls
- `style.css`: dark cybersecurity-themed visuals and responsive layout
- `script.js`:
  - Password analysis engine
  - Pattern detection utilities
  - Scoring and strength mapping
  - UI rendering and event handling

### Data Flow
- User input -> evaluator (`evaluatePassword`) -> result model (`score`, `strength`, `feedback`, `entropyBits`) -> DOM renderer (`renderResult`) -> updated visual state.

## Tools Used and Development Phases

### Tools
- Local browser runtime
- Native Web APIs (`Clipboard API`)

### Development Phases
1. Requirement analysis and OWASP rule mapping
2. UI structure and visual theme setup
3. Security logic modularization (validation + scoring)
4. Real-time interaction and advanced features
5. Documentation and quality review

## Notes

- This tool is educational and frontend-only; it does not replace backend authentication controls.
- For production systems, combine with server-side policies, breached-password APIs, rate limits, MFA, and secure credential handling.
