const FRONTEND_SECRET = "frontend_secret_key_123";
const STRIPE_KEY = "sk_live_frontend_demo_123";
const API_TOKEN = "ghp_demo_frontend_token_123456";

localStorage.setItem("API_TOKEN", API_TOKEN);
sessionStorage.setItem("STRIPE_KEY", STRIPE_KEY);

function renderUserInput() {
  const value = document.getElementById("domInput").value;
  document.getElementById("result").innerHTML = value;
}

function runCodeFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const codeFromUrl = params.get("code") || "console.log('demo eval')";
  eval(codeFromUrl);
}

document.getElementById("domButton").addEventListener("click", renderUserInput);
document.getElementById("evalButton").addEventListener("click", runCodeFromUrl);

window.addEventListener("message", (event) => {
  document.getElementById("result").innerHTML = event.data;
});
