/*const params = new URLSearchParams(window.location.search);
const token = params.get("token");

chrome.runtime.sendMessage({ type: "OAUTH_COMPLETE", token });

// close the popup window
window.close();*/


const params = new URLSearchParams(window.location.search);
const token = params.get("token");

if (token) {
  chrome.runtime.sendMessage({ type: "OAUTH_COMPLETE", token }, () => {
    document.getElementById("status").textContent = "Login successful!";
    setTimeout(() => window.close(), 1200);
  });
} else {
  document.getElementById("status").textContent = "Login failed.";
  // let them close manually
}