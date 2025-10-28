const STREAK_KEY = 'lastResetDateISO';
const DEFAULT_START = '2025-10-09';
const MS_PER_DAY = 24 * 60 * 60 * 1000;

function daysBetweenUTC(fromDate, toDate = new Date()) {
  const a = Date.UTC(fromDate.getFullYear(), fromDate.getMonth(), fromDate.getDate());
  const b = Date.UTC(toDate.getFullYear(),  toDate.getMonth(),  toDate.getDate());
  return Math.max(0, Math.floor((b - a) / MS_PER_DAY));
}

function getLastResetDate() {
  const iso = localStorage.getItem(STREAK_KEY);
  const isoToUse = iso || DEFAULT_START;       // store/read as YYYY-MM-DD
  const [y, m, d] = isoToUse.split('-').map(Number);
  return new Date(y, m - 1, d);
}

function setLastResetDate(date = new Date()) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  localStorage.setItem(STREAK_KEY, `${y}-${m}-${d}`);
}

function ensureMedalShownIfSaved() {
  const iso = localStorage.getItem(STREAK_KEY);     // show medal if ANY saved date exists
  const medalBox = document.querySelector('.medal');
  if (!medalBox) return;

  // Add exactly one medal image
  if (!medalBox.querySelector('img[data-medal-id="streak-started"]')) {
    const img = document.createElement('img');
    img.src = 'images/defender.png';              
    img.alt = 'Streak Medal';
    img.dataset.medalId = 'streak-started';        // avoid duplicates
    img.style.width = '150px';
    img.style.display = 'block';
    img.style.margin = '20px auto';
    medalBox.appendChild(img);
  }
}

function updateStreakDisplay() {
  const last = getLastResetDate();
  const days = daysBetweenUTC(last);

  const el = document.getElementById('daysPassed');
  if (el) {
    el.textContent = `${days} day${days === 1 ? '' : 's'} since last warning`;
  }

  ensureMedalShownIfSaved();
}

function resetStreak(date = new Date()) {
  setLastResetDate(date);        // set to today (or provided date)
  updateStreakDisplay();         // refresh UI
}
window.resetStreak = resetStreak;

document.addEventListener('DOMContentLoaded', () => {
  updateStreakDisplay();

  // testing (click permission) - should be when we get blacklist warning
  document.getElementById('permission')?.addEventListener('click', () => {
    resetStreak(); // sets streak to 0 (start counting from today)
  });
});
