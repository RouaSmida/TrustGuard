# 🔐 TrustGuard — Password Strength Tester

> A professional, cybersecurity-themed password strength tester built on **OWASP** best practices.
> Real-time feedback, entropy estimation, and a secure password generator — all in a sleek dark-mode UI.

---

## 📸 Preview

| Empty state | Weak password | Strong password |
|---|---|---|
| Type or generate a password to begin | Score 0-40 — red bar, red "Weak" label | Score 71-100 — green bar, green "Strong" label |

---

## ✨ Features

| Feature | Details |
|---|---|
| **Real-time strength analysis** | Evaluates on every keystroke — no submit needed |
| **Animated strength bar** | Smooth colour gradient: red → amber → green |
| **Numeric score 0–100** | Weighted scoring across 9 evaluation criteria |
| **Strength label** | Weak / Medium / Strong |
| **Shannon entropy estimate** | Displays theoretical bits of entropy |
| **Dynamic feedback messages** | Actionable, colour-coded suggestions |
| **Common password detection** | Matched against a curated OWASP-aligned blocklist |
| **Sequential / repeated pattern detection** | Flags "1234", "abcd", "aaaa", keyboard walks |
| **Username context check** | Warns when the password contains the username |
| **Generate strong password** | Cryptographically random 16–20 char password |
| **Show / Hide toggle** | Reveals or masks the password field |
| **Copy to clipboard** | One-click copy with visual confirmation |
| **Responsive dark-mode UI** | Works on desktop and mobile |

---

## 🛠 Technologies

| Technology | Role |
|---|---|
| **HTML5** | Semantic markup, ARIA accessibility attributes |
| **CSS3** | Custom properties, animations, responsive grid |
| **Vanilla JavaScript (ES6+)** | Evaluation engine, UI controller, crypto RNG |
| **Web Crypto API** | `crypto.getRandomValues` for secure password generation |
| **Clipboard API** | Modern async clipboard write |

No frameworks, no build step, no dependencies.

---

## 🚀 How to Run

```bash
# Clone the repository
git clone https://github.com/RouaSmida/TrustGuard.git
cd TrustGuard

# Open directly in a browser
open index.html        # macOS
start index.html       # Windows
xdg-open index.html    # Linux
```

Or serve with any static server:

```bash
npx serve .
# → http://localhost:3000
```

---

## 📁 Project Structure

```
TrustGuard/
├── index.html   – UI markup (semantic HTML5 + ARIA)
├── style.css    – Dark-mode cybersecurity theme + animations
├── script.js    – Evaluation logic + UI controller
└── README.md    – This file
```

---

## 🔐 OWASP Compliance

This tool implements guidance from the [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) and [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html):

| OWASP Recommendation | Implementation |
|---|---|
| Minimum 8 characters | Length check with score penalty |
| Encourage 12+ characters | Extra score for 12 / 16 / 20+ char passwords |
| Require mixed character types | Separate scoring for upper, lower, digit, special |
| Reject common passwords | Compared against a curated blocklist |
| Reject sequential patterns | Keyboard walks, alpha sequences, digit runs |
| Reject repeated characters | Regex detection of runs ≥ 3 |
| Avoid user-context data | Username substring check |
| Encourage passphrases | Bonus score for long space-separated phrases |

---

## 📊 Scoring System

```
Total weight: 100 pts

  Length                 30 pts  (scaled by character count)
  Uppercase letters       8 pts
  Lowercase letters       8 pts
  Digits                  8 pts
  Special characters     12 pts
  Full diversity bonus   14 pts  (all 4 classes present)
  Not in common list     10 pts
  No repeated chars       5 pts
  No sequential pattern   5 pts

Penalties:
  Common password       −30 pts
  Contains username     −20 pts
  Repeated chars         −5 pts
  Sequential pattern     −5 pts

Thresholds:
  Weak   :  0 – 40
  Medium : 41 – 70
  Strong : 71 – 100
```

---

## 🧠 Functional Flow

```
User types password
       │
       ▼
PasswordAnalyzer.evaluate(pwd, username)
       │
       ├─ Length score
       ├─ Character class checks (upper / lower / digit / special)
       ├─ Diversity bonus
       ├─ Common password lookup
       ├─ Repeated character check
       ├─ Sequential pattern check
       └─ Username context check
       │
       ▼
{ score, level, entropy, feedback[] }
       │
       ▼
UIController.renderResult()
       │
       ├─ Animate meter bar (width + colour)
       ├─ Update strength label & score
       ├─ Display entropy estimate
       └─ Render feedback list items
```

---

## 🔑 Password Security Concepts

### What makes a password strong?
A strong password is **long**, **random**, and **unique**. The key factors are:

1. **Length** — Each additional character multiplies the search space exponentially.
2. **Character diversity** — Using uppercase, lowercase, digits, and symbols expands the effective alphabet.
3. **Entropy** — Measured in bits; each bit doubles the number of guesses needed. 60+ bits is considered strong.
4. **Unpredictability** — Avoids dictionary words, names, keyboard patterns, and personal data.

### Shannon Entropy
`H = L × log₂(N)` where `L` = password length and `N` = pool size.

| Character set used | Pool size |
|---|---|
| Lowercase only | 26 |
| + Uppercase | 52 |
| + Digits | 62 |
| + Special chars | ~94 |

### OWASP Password Requirements Summary
- Minimum 8 chars (12 recommended, 16+ ideal)
- No forced complexity rules that reduce usability
- Block known-bad passwords using a deny-list
- Allow all printable Unicode characters
- Encourage passphrases

---

## 🏗 High-Level Design

```
┌─────────────────────────────────────────────────────┐
│                   index.html  (View)                 │
│  ┌───────────────┐  ┌──────────────────────────────┐ │
│  │  Input Fields │  │  Strength Meter + Feedback    │ │
│  │  (password,   │  │  (bar, label, score, entropy, │ │
│  │   username)   │  │   feedback list)              │ │
│  └──────┬────────┘  └──────────────────────────────┘ │
└─────────┼───────────────────────────────────────────┘
          │ DOM events (input, click)
          ▼
┌─────────────────────────────────────────────────────┐
│              UIController  (script.js)               │
│  Listens to events → calls Analyzer → renders result │
└─────────┬──────────────────────┬────────────────────┘
          │                      │
          ▼                      ▼
┌──────────────────┐   ┌─────────────────────┐
│ PasswordAnalyzer │   │  PasswordGenerator  │
│                  │   │                     │
│ evaluate(pwd,    │   │  generate()         │
│   username)      │   │  → crypto random    │
│                  │   │    16-20 char pwd   │
│ → score 0-100    │   └─────────────────────┘
│ → level          │
│ → entropy bits   │
│ → feedback[]     │
└──────────────────┘
```

---

## 📘 Development Phases

| Phase | Work |
|---|---|
| 1. Research | OWASP guidelines, entropy theory, common password lists |
| 2. Logic design | Scoring weights, penalty rules, feedback messages |
| 3. Core module | `PasswordAnalyzer` — pure functions, unit-testable |
| 4. Generator | `PasswordGenerator` — Web Crypto API |
| 5. UI shell | HTML structure, semantic elements, ARIA roles |
| 6. Styling | Dark-mode theme, animated bar, responsive layout |
| 7. Integration | `UIController` wiring DOM ↔ logic |
| 8. QA | Edge cases (empty, very long, emoji, Unicode) |

---

## 📜 License

MIT — free to use, modify, and distribute.

---

*Built with ❤️ and cybersecurity in mind.*
