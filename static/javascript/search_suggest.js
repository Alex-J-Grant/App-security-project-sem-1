// debounce helper
function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

const input = document.getElementById("global-search");
const suggestionsEl = document.getElementById("suggestions");
let currentItems = []; // flattened list for navigation

function escapeHtml(str) {
  return str.replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
}

async function fetchSuggestions(q) {
  if (!q) {
    hideSuggestions();
    return;
  }
  try {
    const res = await fetch(`/search_suggestions?q=${encodeURIComponent(q)}`);
    if (!res.ok) return;
    const data = await res.json();
    renderSuggestions(data);
  } catch (e) {
    console.error("Suggestion fetch error:", e);
    hideSuggestions();
  }
}

function renderSuggestions({ users, communities }) {
  let html = "";
  currentItems = [];

  if (communities.length) {
    html += `<div class="px-2 fw-bold small text-muted">Communities</div>`;
    communities.forEach(c => {
      const item = {
        type: "community",
        value: c.name,
        href: `/communities/${encodeURIComponent(c.name)}`,
      };
      currentItems.push(item);
      html += `
        <a href="${item.href}" data-idx="${currentItems.length-1}" class="list-group-item list-group-item-action d-flex align-items-center suggestion-item" style="border:0px;">
          <img src="${escapeHtml(c.pfp)}" alt="pfp" class="rounded-circle me-2" style="width:32px; height:32px; object-fit:cover;">
          <div class="flex-grow-1">
            <div class="fw-semibold">c/${escapeHtml(c.name)}</div>
            <div class="small text-muted">Community</div>
          </div>
        </a>`;
    });
  }

  if (users.length) {
    html += `<div class="px-2 fw-bold small text-muted mt-1">Users</div>`;
    users.forEach(u => {
      const item = {
        type: "user",
        value: u.username,
        href: `/users/${encodeURIComponent(u.username)}`,
      };
      currentItems.push(item);
      html += `
        <a href="${item.href}" data-idx="${currentItems.length-1}" class="list-group-item list-group-item-action d-flex align-items-center suggestion-item" style="border:0px;">
          <img src="${escapeHtml(u.pfp)}" alt="pfp" class="rounded-circle me-2" style="width:32px; height:32px; object-fit:cover;">
          <div class="flex-grow-1">
            <div class="fw-semibold">u/${escapeHtml(u.username)}</div>
            <div class="small text-muted">User</div>
          </div>
        </a>`;
    });
  }

  if (!html) {
    html = `<div class="list-group-item text-muted">No matches</div>`;
    currentItems = [];
  }

  suggestionsEl.innerHTML = html;
  suggestionsEl.style.display = "block";
  focusedIndex = -1;
  updateFocus();
}

// hide dropdown
function hideSuggestions() {
  suggestionsEl.style.display = "none";
  currentItems = [];
  focusedIndex = -1;
}

function updateFocus() {
  const items = suggestionsEl.querySelectorAll(".suggestion-item");
  items.forEach(el => el.classList.remove("active"));
  if (focusedIndex >= 0 && focusedIndex < items.length) {
    items[focusedIndex].classList.add("active");
    // ensure visibility
    items[focusedIndex].scrollIntoView({ block: "nearest" });
  }
}


// click outside to close
document.addEventListener("click", (e) => {
  if (!suggestionsEl.contains(e.target) && e.target !== input) {
    hideSuggestions();
  }
});

// debounce input
input.addEventListener("input", debounce((e) => {
  fetchSuggestions(e.target.value);
}, 200));

input.addEventListener("keypress", (e) => {
  if (e.key === "Enter" && focusedIndex === -1) {
    const q = input.value.trim();
    if (q) {
      window.location.href = `/search?q=${encodeURIComponent(q)}`;
    }
  }
});