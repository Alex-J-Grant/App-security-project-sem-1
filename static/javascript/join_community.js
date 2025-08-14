// like.js
document.addEventListener("DOMContentLoaded", () => {
  const inFlight = new Set(); // track post_ids with ongoing request

  document.body.addEventListener("click", async (e) => {
    const btn = e.target.closest(".join-btn");
    if (!btn) return; // guard early
    e.preventDefault();

    const commId = btn.dataset.commId;
    // if no community ID in the data then cancel
    if (!commId) {
      return;
    }

    if (inFlight.has(commId)) {
      console.log("Request already in flight for", commId);
      return;
    }


    //get the like count element
    const countSpan = document.querySelector(".member_count");

    //check if its currently liked
    const currentlyJoined = btn.dataset.joined === "true";

    //set action based on if its liked
    const action = currentlyJoined ? "leave" : "join";

    console.log(`Post ${commId} currentlyLiked=${currentlyJoined}, action=${action}`);

    inFlight.add(commId);
    btn.disabled = true;

    try {
      const headers = { "Accept": "application/json" };
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
      headers["X-CSRFToken"] = csrfToken

      const resp = await fetch(`/join_community/${encodeURIComponent(commId)}/${action}`, {
        method: "POST",
        headers
      });

      if (resp.status === 429) {
        showInlineTooltip(btn, "Too fast, slow down");
        return;
      }
      if (resp.status === 401){
        window.location.href = "/account/login";;
      }
      if (!resp.ok) {
        return;
      }

      const data = await resp.json();

      // If the server agrees the state is unchanged, we can still update UI to reflect authoritative value
      btn.dataset.joined = data.joined ? "true" : "false";
      if (countSpan) countSpan.textContent = String(data.member_count).concat(" Members");

      if (btn) {
        if (data.joined) {
          btn.classList.remove("btn-primary");
          btn.classList.add("btn-danger");
          btn.textContent = "Leave"
        } else {
          btn.classList.remove("btn-danger");
          btn.classList.add("btn-primary");
          btn.textContent = "Join"
        }
      }
    } catch (err) {
      console.error("Network error on like:", err);
    } finally {
      inFlight.delete(commId);
      btn.disabled = false;
    }
  });
});

// tooltip helper remains unchanged
function showInlineTooltip(btn, msg) {
  let tip = btn.querySelector(".inline-tooltip");
  if (!tip) {
    tip = document.createElement("div");
    tip.className = "inline-tooltip position-absolute small bg-danger text-white px-2 py-1 rounded";
    tip.style.top = "-30px";
    tip.style.left = "50%";
    tip.style.transform = "translateX(-50%)";
    tip.style.whiteSpace = "nowrap";
    tip.style.zIndex = "2000";
    btn.style.position = "relative";
    btn.appendChild(tip);
  }
  tip.textContent = msg;
  tip.style.opacity = "1";

  setTimeout(() => {
    tip.style.transition = "opacity .4s";
    tip.style.opacity = "0";
    setTimeout(() => tip.remove(), 400);
  }, 1500);
}
