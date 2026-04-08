// OWASP-inspired baseline list for weak passwords.
const COMMON_PASSWORDS = new Set([
  "123456", "123456789", "qwerty", "password", "12345", "12345678",
  "111111", "abc123", "password1", "123123", "000000", "iloveyou",
  "admin", "welcome", "letmein", "dragon"
]);
const MIN_SEQUENTIAL_LENGTH = 4;
const GENERATED_PASSWORD_DEFAULT_LENGTH = 18;
// Includes quotes, forward slash (/), and backslash (\) with JS escaping.
const SPECIAL_CHAR_SET = "!@#$%^&*()_+-=[]{}|;:,.<>?`~'\"\\\\/";

const patterns = {
  uppercase: /[A-Z]/,
  lowercase: /[a-z]/,
  number: /\d/,
  special: /[^A-Za-z0-9\s]/
};

const ui = {
  username: document.getElementById("username"),
  password: document.getElementById("password"),
  toggle: document.getElementById("toggle-visibility"),
  generate: document.getElementById("generate-password"),
  copy: document.getElementById("copy-password"),
  meter: document.getElementById("meter-bar"),
  label: document.getElementById("strength-label"),
  score: document.getElementById("score"),
  entropy: document.getElementById("entropy"),
  feedback: document.getElementById("feedback")
};

function hasSequentialPattern(value) {
  const normalized = value.toLowerCase();
  for (let i = 0; i <= normalized.length - MIN_SEQUENTIAL_LENGTH; i++) {
    const segment = normalized.slice(i, i + MIN_SEQUENTIAL_LENGTH);
    let ascending = true;
    let descending = true;

    for (let j = 1; j < segment.length; j++) {
      const diff = segment.charCodeAt(j) - segment.charCodeAt(j - 1);
      ascending = ascending && diff === 1;
      descending = descending && diff === -1;
    }

    if (ascending || descending) return true;
  }
  return false;
}

function hasRepetitivePattern(value) {
  return /(.)\1{2,}/.test(value);
}

function estimateEntropy(password, poolSize) {
  if (!password.length || poolSize <= 1) return 0;
  return Math.round(password.length * Math.log2(poolSize));
}

function getCharacterPoolSize(password) {
  let pool = 0;
  if (patterns.lowercase.test(password)) pool += 26;
  if (patterns.uppercase.test(password)) pool += 26;
  if (patterns.number.test(password)) pool += 10;
  if (patterns.special.test(password)) pool += SPECIAL_CHAR_SET.length;
  return pool;
}

// Main scoring logic separated from DOM updates for maintainability.
function evaluatePassword(password, username = "") {
  let score = 0;
  const feedback = [];

  const trimmedUsername = username.trim().toLowerCase();
  const loweredPassword = password.toLowerCase();
  const length = password.length;

  // Length weighting
  if (length >= 8) score += 15;
  if (length >= 10) score += 10;
  if (length >= 12) score += 10;
  if (length >= 16) score += 10;

  // Character diversity weighting
  const hasUpper = patterns.uppercase.test(password);
  const hasLower = patterns.lowercase.test(password);
  const hasNumber = patterns.number.test(password);
  const hasSpecial = patterns.special.test(password);

  if (hasUpper) score += 10;
  else feedback.push("Add uppercase letters.");

  if (hasLower) score += 10;
  else feedback.push("Add lowercase letters.");

  if (hasNumber) score += 10;
  else feedback.push("Add numbers.");

  if (hasSpecial) score += 12;
  else feedback.push("Add special characters.");

  // Passphrase encouragement
  const hasSpaces = /\s/.test(password);
  const words = password.trim().split(/\s+/).filter(Boolean);
  if (length >= 16 && hasSpaces && words.length >= 3) {
    score += 8;
    feedback.push("Great use of a passphrase-style password.");
  }

  // Penalties for weak patterns
  if (COMMON_PASSWORDS.has(loweredPassword)) {
    score -= 35;
    feedback.push("Avoid common passwords.");
  }

  if (hasRepetitivePattern(password)) {
    score -= 15;
    feedback.push("Avoid repeated character patterns.");
  }

  if (hasSequentialPattern(password)) {
    score -= 15;
    feedback.push("Avoid sequential patterns (e.g., abcd, 1234).");
  }

  if (trimmedUsername && loweredPassword.includes(trimmedUsername)) {
    score -= 20;
    feedback.push("Do not include user-related information.");
  }

  if (length < 8) {
    score -= 10;
    feedback.push("Increase password length to at least 8 characters.");
  } else if (length < 12) {
    feedback.push("Aim for 12+ characters for stronger protection.");
  }

  score = Math.max(0, Math.min(100, score));

  let strength = "Weak";
  if (score > 70) strength = "Strong";
  else if (score > 40) strength = "Medium";

  const poolSize = getCharacterPoolSize(password);
  const entropyBits = estimateEntropy(password, poolSize);

  if (!password) {
    return {
      score: 0,
      strength: "Weak",
      feedback: ["Start typing to see recommendations."],
      entropyBits: 0
    };
  }

  if (feedback.length === 0) {
    feedback.push("Good password. Keep it unique and never reuse it.");
  }

  return { score, strength, feedback, entropyBits };
}

function meterColor(score) {
  if (score <= 40) return "var(--danger)";
  if (score <= 70) return "var(--warning)";
  return "var(--success)";
}

function renderResult(result) {
  ui.score.textContent = `${result.score} / 100`;
  ui.label.textContent = result.strength;
  ui.label.className = `strength-label ${result.strength.toLowerCase()}`;
  ui.meter.style.width = `${result.score}%`;
  ui.meter.style.backgroundColor = meterColor(result.score);
  ui.entropy.textContent = `Estimated entropy: ${result.entropyBits} bits`;
  ui.feedback.innerHTML = result.feedback.map((item) => `<li>${item}</li>`).join("");
}

function updateStrength() {
  const result = evaluatePassword(ui.password.value, ui.username.value || "");
  renderResult(result);
}

function secureRandomInt(max) {
  if (!Number.isInteger(max) || max <= 0) {
    throw new RangeError("secureRandomInt requires a positive integer max.");
  }
  const maxUint32 = 0x100000000;
  const acceptableLimit = Math.floor(maxUint32 / max) * max;
  const buffer = new Uint32Array(1);
  let value;

  do {
    window.crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= acceptableLimit);

  return value % max;
}

function randomChar(charset) {
  return charset[secureRandomInt(charset.length)];
}

// 18 chars offers a strong default while keeping generated passwords practical to use.
function generateStrongPassword(length = GENERATED_PASSWORD_DEFAULT_LENGTH) {
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const nums = "0123456789";
  const all = lower + upper + nums + SPECIAL_CHAR_SET;

  // Ensure baseline diversity by forcing one char from each set.
  const required = [randomChar(lower), randomChar(upper), randomChar(nums), randomChar(SPECIAL_CHAR_SET)];
  const generated = [...required];

  while (generated.length < length) {
    generated.push(randomChar(all));
  }

  for (let i = generated.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [generated[i], generated[j]] = [generated[j], generated[i]];
  }

  return generated.join("");
}

ui.password.addEventListener("input", updateStrength);
ui.username.addEventListener("input", updateStrength);

ui.toggle.addEventListener("click", () => {
  const isHidden = ui.password.type === "password";
  ui.password.type = isHidden ? "text" : "password";
  ui.toggle.textContent = isHidden ? "Hide" : "Show";
});

ui.generate.addEventListener("click", () => {
  ui.password.value = generateStrongPassword();
  updateStrength();
});

ui.copy.addEventListener("click", async () => {
  if (!ui.password.value) return;
  try {
    await navigator.clipboard.writeText(ui.password.value);
    ui.copy.textContent = "Copied";
    setTimeout(() => {
      ui.copy.textContent = "Copy";
    }, 1000);
  } catch {
    ui.copy.textContent = "Copy failed";
    setTimeout(() => {
      ui.copy.textContent = "Copy";
    }, 1000);
  }
});

updateStrength();
