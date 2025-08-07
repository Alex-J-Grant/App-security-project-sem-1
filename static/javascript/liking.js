// like.js
document.addEventListener("DOMContentLoaded", () => {
  const inFlight = new Set(); // track post_ids with ongoing request

  document.body.addEventListener("click", async (e) => {
    const btn = e.target.closest(".like-btn");
    if (!btn) return; // guard early
    e.preventDefault();

    const postId = btn.dataset.postId;
    // if no postID in the data then cancel
    if (!postId) {
      return;
    }

    if (inFlight.has(postId)) {
      console.log("Request already in flight for", postId);
      return;
    }

    //select the icon in the button
    const icon = btn.querySelector("i");
    //get the like count element
    const countSpan = btn.querySelector(".like-count");

    //check if its currently liked
    const currentlyLiked = btn.dataset.liked === "true";

    //set action based on if its liked
    const action = currentlyLiked ? "unlike" : "like";

    console.log(`[like.js] Post ${postId} currentlyLiked=${currentlyLiked}, action=${action}`);

    inFlight.add(postId);
    btn.disabled = true;

    try {
      const headers = { "Accept": "application/json" };
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
      headers["X-CSRFToken"] = csrfToken

      const resp = await fetch(`/like/${encodeURIComponent(postId)}/${action}`, {
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
      btn.dataset.liked = data.liked ? "true" : "false";

      if (countSpan) countSpan.textContent = data.like_count;

      if (icon) {
        if (data.liked) {
          icon.classList.remove("bi-hand-thumbs-up");
          icon.classList.add("bi-hand-thumbs-up-fill");
          btn.classList.add("text-primary");
        } else {
          icon.classList.remove("bi-hand-thumbs-up-fill");
          icon.classList.add("bi-hand-thumbs-up");
          btn.classList.remove("text-primary");
        }
      }
    } catch (err) {
      console.error("Network error on like:", err);
    } finally {
      inFlight.delete(postId);
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
