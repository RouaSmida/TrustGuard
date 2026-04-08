/**
 * TrustGuard – script.js
 * =====================================================================
 * OWASP-based Password Strength Tester
 *
 * Architecture:
 *   • PasswordAnalyzer  – pure evaluation & scoring logic (no DOM)
 *   • PasswordGenerator – secure random password builder
 *   • UI Controller     – wires DOM events to the analyzer / generator
 * =====================================================================
 */

/* =====================================================================
   SECTION 1 – CONSTANTS & DICTIONARIES
   ===================================================================== */

/** OWASP-aligned list of the most common / breached passwords. */
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '123456', '1234567', '12345678',
  '123456789', '1234567890', 'qwerty', 'qwerty123', 'abc123', 'iloveyou',
  'admin', 'letmein', 'monkey', 'dragon', 'master', 'sunshine', 'princess',
  'welcome', 'shadow', 'superman', 'michael', 'football', 'baseball',
  'trustno1', 'hello', 'charlie', 'donald', 'pass', 'test', 'root',
  'toor', 'changeme', 'passw0rd', 'pa$$word', '111111', '000000',
  'aaaaaa', 'qqqqq', 'zxcvbn', 'qazwsx', '1q2w3e4r', 'login', 'access',
]);

/** Keyboard rows used for sequential pattern detection. */
const KEYBOARD_SEQUENCES = [
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
  'qwertzuiop', 'azertyuiop',
  '1234567890',
];

/** Alphabet and digit rows for sequential pattern detection. */
const ALPHA_SEQUENCE  = 'abcdefghijklmnopqrstuvwxyz';
const DIGIT_SEQUENCE  = '0123456789';

/* Scoring weights (sum to 100 for a "perfect" password) */
const WEIGHTS = {
  length:       30,   // character count contribution
  uppercase:     8,   // contains A-Z
  lowercase:     8,   // contains a-z
  digits:        8,   // contains 0-9
  special:      12,   // contains special chars
  diversity:    14,   // all four character classes present
  noCommon:     10,   // not a known-bad password
  noRepeat:      5,   // no long run of repeated chars
  noSequence:    5,   // no keyboard / alphabetical run
};

/* Score thresholds */
const THRESHOLD = { weak: 40, medium: 70 };

/* Minimum recommended length (OWASP: 8, bonus at 12+) */
const MIN_LENGTH          = 8;
const LONG_PASSPHRASE_LEN = 20;

/* Character classes for generation */
const CHARS = {
  upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower:   'abcdefghijklmnopqrstuvwxyz',
  digits:  '0123456789',
  special: '!@#$%^&*()-_=+[]{}|;:,.<>?',
};


/* =====================================================================
   SECTION 2 – PASSWORD ANALYZER (pure logic, no DOM)
   ===================================================================== */

const PasswordAnalyzer = (() => {

  /**
   * Calculate Shannon entropy (bits) for the password.
   * Pool size is derived from the character classes present.
   * @param {string} pwd
   * @returns {number}
   */
  function calcEntropy(pwd) {
    if (!pwd) return 0;
    let pool = 0;
    if (/[a-z]/.test(pwd))                         pool += 26;
    if (/[A-Z]/.test(pwd))                         pool += 26;
    if (/[0-9]/.test(pwd))                         pool += 10;
    if (/[^a-zA-Z0-9]/.test(pwd))                  pool += 32;
    return pool > 0 ? Math.floor(pwd.length * Math.log2(pool)) : 0;
  }

  /**
   * Check if `str` contains a sequential sub-string of length >= `minLen`.
   * Tests both forward and reverse directions.
   * @param {string} str
   * @param {number} minLen
   * @returns {boolean}
   */
  function hasSequentialPattern(str, minLen = 4) {
    const lower = str.toLowerCase();
    const sequences = [
      ...KEYBOARD_SEQUENCES,
      ALPHA_SEQUENCE,
      DIGIT_SEQUENCE,
    ];
    for (const seq of sequences) {
      const rev = seq.split('').reverse().join('');
      for (const s of [seq, rev]) {
        for (let i = 0; i <= s.length - minLen; i++) {
          if (lower.includes(s.slice(i, i + minLen))) return true;
        }
      }
    }
    return false;
  }

  /**
   * Check for runs of the same character (e.g. "aaaaaa").
   * @param {string} str
   * @param {number} threshold
   * @returns {boolean}
   */
  function hasRepeatedChars(str, threshold = 3) {
    return /(.)\1{2,}/.test(str) && (() => {
      const match = str.match(/(.)\1+/g);
      return match ? match.some(m => m.length >= threshold) : false;
    })();
  }

  /**
   * Check if the password contains the username (case-insensitive).
   * @param {string} pwd
   * @param {string} username
   * @returns {boolean}
   */
  function containsUsername(pwd, username) {
    if (!username || username.length < 3) return false;
    return pwd.toLowerCase().includes(username.toLowerCase());
  }

  /**
   * Compute a 0-100 score and collect granular feedback items.
   *
   * @param {string} pwd      – the password to evaluate
   * @param {string} username – optional username for context check
   * @returns {{ score: number, level: string, entropy: number, feedback: Array<{type:string, msg:string}> }}
   */
  function evaluate(pwd, username = '') {
    const feedback = [];
    let score = 0;

    if (!pwd) {
      return { score: 0, level: 'weak', entropy: 0, feedback: [] };
    }

    /* ── 1. Length scoring (up to WEIGHTS.length pts) ── */
    const len = pwd.length;
    let lengthScore = 0;
    if (len >= LONG_PASSPHRASE_LEN) {
      lengthScore = WEIGHTS.length;                      // full marks for long passphrase
      feedback.push({ type: 'good', msg: '✅ Excellent length (passphrase-level)' });
    } else if (len >= 16) {
      lengthScore = WEIGHTS.length * 0.9;
      feedback.push({ type: 'good', msg: '✅ Very good length (16+ characters)' });
    } else if (len >= 12) {
      lengthScore = WEIGHTS.length * 0.75;
      feedback.push({ type: 'good', msg: '✅ Good length (12+ characters)' });
    } else if (len >= MIN_LENGTH) {
      lengthScore = WEIGHTS.length * 0.5;
      feedback.push({ type: 'warn', msg: '⚠️ Meets minimum length — aim for 12+ characters' });
    } else {
      lengthScore = Math.max(0, (len / MIN_LENGTH) * WEIGHTS.length * 0.4);
      feedback.push({ type: 'bad', msg: `❌ Too short — use at least ${MIN_LENGTH} characters` });
    }
    score += lengthScore;

    /* ── 2. Character class checks ── */
    const hasUpper   = /[A-Z]/.test(pwd);
    const hasLower   = /[a-z]/.test(pwd);
    const hasDigit   = /[0-9]/.test(pwd);
    const hasSpecial = /[^a-zA-Z0-9]/.test(pwd);

    if (hasUpper) {
      score += WEIGHTS.uppercase;
      feedback.push({ type: 'good', msg: '✅ Contains uppercase letters' });
    } else {
      feedback.push({ type: 'bad',  msg: '❌ Add uppercase letters (A-Z)' });
    }

    if (hasLower) {
      score += WEIGHTS.lowercase;
    } else {
      feedback.push({ type: 'bad', msg: '❌ Add lowercase letters (a-z)' });
    }

    if (hasDigit) {
      score += WEIGHTS.digits;
      feedback.push({ type: 'good', msg: '✅ Contains numbers' });
    } else {
      feedback.push({ type: 'bad', msg: '❌ Add numbers (0-9)' });
    }

    if (hasSpecial) {
      score += WEIGHTS.special;
      feedback.push({ type: 'good', msg: '✅ Contains special characters' });
    } else {
      feedback.push({ type: 'bad', msg: '❌ Add special characters (!@#$%…)' });
    }

    /* ── 3. Diversity bonus (all four classes present) ── */
    const classCount = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
    if (classCount === 4) {
      score += WEIGHTS.diversity;
      feedback.push({ type: 'good', msg: '✅ Great character diversity' });
    } else if (classCount === 3) {
      score += WEIGHTS.diversity * 0.5;
      feedback.push({ type: 'warn', msg: '⚠️ Mix more character types for better strength' });
    } else {
      feedback.push({ type: 'bad', msg: '❌ Use at least 3 different character types' });
    }

    /* ── 4. Common password penalty ── */
    if (COMMON_PASSWORDS.has(pwd.toLowerCase())) {
      score = Math.max(0, score - 30);           // heavy penalty
      feedback.push({ type: 'bad', msg: '🚫 This is a commonly breached password' });
    } else {
      score += WEIGHTS.noCommon;
      feedback.push({ type: 'good', msg: '✅ Not found in common password lists' });
    }

    /* ── 5. Repeated characters penalty ── */
    if (hasRepeatedChars(pwd)) {
      score = Math.max(0, score - WEIGHTS.noRepeat);
      feedback.push({ type: 'warn', msg: '⚠️ Avoid repeated characters (e.g. "aaa")' });
    } else {
      score += WEIGHTS.noRepeat;
    }

    /* ── 6. Sequential patterns penalty ── */
    if (hasSequentialPattern(pwd)) {
      score = Math.max(0, score - WEIGHTS.noSequence);
      feedback.push({ type: 'warn', msg: '⚠️ Avoid sequential patterns (e.g. "1234", "abcd")' });
    } else {
      score += WEIGHTS.noSequence;
    }

    /* ── 7. Username context penalty ── */
    if (containsUsername(pwd, username)) {
      score = Math.max(0, score - 20);
      feedback.push({ type: 'bad', msg: '🚫 Password should not contain your username' });
    }

    /* ── 8. Passphrase encouragement ── */
    if (len >= LONG_PASSPHRASE_LEN && pwd.includes(' ')) {
      score = Math.min(100, score + 5);
      feedback.push({ type: 'good', msg: '✅ Passphrase detected — excellent choice!' });
    }

    /* ── 9. Hard cap: passwords shorter than minimum can never leave "weak" tier ── */
    if (len < MIN_LENGTH) {
      score = Math.min(score, THRESHOLD.weak);
    }

    /* ── 10. Cap score to [0, 100] ── */
    score = Math.min(100, Math.max(0, Math.round(score)));

    /* ── 11. Determine level ── */
    let level;
    if (score <= THRESHOLD.weak)       level = 'weak';
    else if (score <= THRESHOLD.medium) level = 'medium';
    else                                level = 'strong';

    const entropy = calcEntropy(pwd);

    return { score, level, entropy, feedback };
  }

  /* Public API */
  return { evaluate, calcEntropy };
})();


/* =====================================================================
   SECTION 3 – PASSWORD GENERATOR
   ===================================================================== */

const PasswordGenerator = (() => {

  /**
   * Generate a cryptographically random integer in [0, max).
   * Uses rejection sampling to eliminate modulo bias.
   * Falls back to Math.random when the Web Crypto API is unavailable.
   * @param {number} max
   * @returns {number}
   */
  function secureRandom(max) {
    if (window.crypto && window.crypto.getRandomValues) {
      // Rejection sampling: discard values in the biased tail region so that
      // every output value has an exactly equal probability.
      const limit = Math.floor(0x100000000 / max) * max; // largest multiple of max ≤ 2^32
      const arr = new Uint32Array(1);
      do {
        window.crypto.getRandomValues(arr);
      } while (arr[0] >= limit);
      return arr[0] % max;
    }
    return Math.floor(Math.random() * max);
  }

  /**
   * Fisher-Yates shuffle (in-place) using secureRandom.
   * @param {Array} arr
   */
  function shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = secureRandom(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  /**
   * Build a strong password that satisfies OWASP recommendations:
   *  – At least 16 characters
   *  – At least one of each character class
   *  – No sequential or repeated patterns
   *
   * @returns {string}
   */
  function generate() {
    const all = CHARS.upper + CHARS.lower + CHARS.digits + CHARS.special;
    const len = 16 + secureRandom(5);   // 16–20 chars

    // Guarantee at least one of each class
    const required = [
      CHARS.upper  [secureRandom(CHARS.upper.length)],
      CHARS.lower  [secureRandom(CHARS.lower.length)],
      CHARS.digits [secureRandom(CHARS.digits.length)],
      CHARS.special[secureRandom(CHARS.special.length)],
    ];

    // Fill remaining positions
    const rest = Array.from({ length: len - required.length }, () => all[secureRandom(all.length)]);

    return shuffle([...required, ...rest]).join('');
  }

  return { generate };
})();


/* =====================================================================
   SECTION 4 – UI CONTROLLER
   ===================================================================== */

(function UIController() {

  /* ── DOM references ── */
  const passwordInput     = document.getElementById('password-input');
  const usernameInput     = document.getElementById('username-input');
  const toggleVisibility  = document.getElementById('toggle-visibility');
  const eyeOpen           = toggleVisibility.querySelector('.eye-open');
  const eyeOff            = toggleVisibility.querySelector('.eye-off');
  const meterBar          = document.getElementById('meter-bar');
  const meterTrack        = meterBar.parentElement;
  const strengthLabel     = document.getElementById('strength-label');
  const scoreValue        = document.getElementById('score-value');
  const entropyValue      = document.getElementById('entropy-value');
  const feedbackList      = document.getElementById('feedback-list');
  const generateBtn       = document.getElementById('generate-btn');
  const copyBtn           = document.getElementById('copy-btn');
  const copyLabel         = document.getElementById('copy-label');

  /* ── Update the UI with an evaluation result ── */
  function renderResult({ score, level, entropy, feedback }) {
    // Strength bar
    meterBar.style.width = score + '%';
    meterBar.className   = 'meter-bar ' + level;
    meterTrack.setAttribute('aria-valuenow', score);

    // Label & score
    strengthLabel.textContent  = level.charAt(0).toUpperCase() + level.slice(1);
    strengthLabel.className    = 'strength-label ' + level;
    scoreValue.textContent     = score;

    // Entropy
    entropyValue.textContent = entropy > 0 ? entropy + ' bits' : '— bits';

    // Feedback items
    feedbackList.innerHTML = '';
    feedback.forEach(({ type, msg }) => {
      const li = document.createElement('li');
      li.className = 'feedback-item ' + type;
      li.textContent = msg;
      feedbackList.appendChild(li);
    });

    // Enable copy only when there is a password
    copyBtn.disabled = !passwordInput.value;
  }

  /* ── Reset UI to empty state ── */
  function resetUI() {
    meterBar.style.width       = '0%';
    meterBar.className         = 'meter-bar';
    strengthLabel.textContent  = '—';
    strengthLabel.className    = 'strength-label';
    scoreValue.textContent     = '0';
    entropyValue.textContent   = '— bits';
    feedbackList.innerHTML     = '';
    copyBtn.disabled           = true;
    meterTrack.setAttribute('aria-valuenow', 0);
  }

  /* ── Event: password input changes ── */
  function onPasswordInput() {
    const pwd      = passwordInput.value;
    const username = usernameInput.value.trim();

    if (!pwd) {
      resetUI();
      return;
    }

    const result = PasswordAnalyzer.evaluate(pwd, username);
    renderResult(result);
  }

  /* ── Event: username input changes (re-evaluate password) ── */
  function onUsernameInput() {
    if (passwordInput.value) onPasswordInput();
  }

  /* ── Event: toggle show/hide password ── */
  function onToggleVisibility() {
    const isHidden = passwordInput.type === 'password';
    passwordInput.type = isHidden ? 'text' : 'password';
    eyeOpen.classList.toggle('hidden',  isHidden);
    eyeOff .classList.toggle('hidden', !isHidden);
    toggleVisibility.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
  }

  /* ── Event: generate strong password ── */
  function onGenerate() {
    const pwd = PasswordGenerator.generate();
    passwordInput.value = pwd;
    // Make password visible so the user can see what was generated
    passwordInput.type = 'text';
    eyeOpen.classList.add('hidden');
    eyeOff .classList.remove('hidden');
    toggleVisibility.setAttribute('aria-label', 'Hide password');
    onPasswordInput();
    passwordInput.focus();
  }

  /* ── Event: copy to clipboard ── */
  function onCopy() {
    const pwd = passwordInput.value;
    if (!pwd) return;

    navigator.clipboard.writeText(pwd).then(() => {
      copyLabel.textContent = 'Copied!';
      copyBtn.classList.add('copied');
      setTimeout(() => {
        copyLabel.textContent = 'Copy';
        copyBtn.classList.remove('copied');
      }, 2000);
    }).catch(() => {
      // Fallback for older browsers
      const ta = document.createElement('textarea');
      ta.value = pwd;
      ta.style.position = 'fixed';
      ta.style.opacity  = '0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        copyLabel.textContent = 'Copied!';
        copyBtn.classList.add('copied');
        setTimeout(() => {
          copyLabel.textContent = 'Copy';
          copyBtn.classList.remove('copied');
        }, 2000);
      } catch (_) { /* silent */ }
      document.body.removeChild(ta);
    });
  }

  /* ── Attach event listeners ── */
  passwordInput   .addEventListener('input',  onPasswordInput);
  usernameInput   .addEventListener('input',  onUsernameInput);
  toggleVisibility.addEventListener('click',  onToggleVisibility);
  generateBtn     .addEventListener('click',  onGenerate);
  copyBtn         .addEventListener('click',  onCopy);

  /* ── Initial render ── */
  resetUI();

})();
