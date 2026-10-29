"use strict";

const vscode = acquireVsCodeApi();
const messages = document.getElementById("messages");
const form = document.getElementById("composer");
const prompt = document.getElementById("prompt");
const sendButton = document.getElementById("send");
const status = document.getElementById("status");
const welcome = document.getElementById("welcome");
let busy = false;

function appendMessage(role, html) {
  welcome.hidden = true;
  const article = document.createElement("article");
  article.className = `message ${role}`;
  const label = document.createElement("div");
  label.className = "message-label";
  label.textContent = role === "assistant" ? "Assistant" : "You";
  const content = document.createElement("div");
  content.className = "message-content";
  content.innerHTML = html;
  article.append(label, content);
  messages.appendChild(article);
  messages.scrollTop = messages.scrollHeight;
}

form.addEventListener("submit", event => {
  event.preventDefault();
  const text = prompt.value.trim();
  if (!text || busy) return;
  prompt.value = "";
  vscode.postMessage({ type: "send", text });
});

prompt.addEventListener("keydown", event => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    form.requestSubmit();
  }
});

document.getElementById("clear").addEventListener("click", () => {
  vscode.postMessage({ type: "clear" });
});

messages.addEventListener("click", event => {
  const button = event.target.closest(".copy-code");
  if (!button) return;
  const code = button.closest(".code-block")?.querySelector("pre code")?.textContent;
  if (code !== undefined) {
    vscode.postMessage({ type: "copy", text: code });
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = "Copy"; }, 1200);
  }
});

window.addEventListener("message", event => {
  const message = event.data;
  if (message.type === "message") appendMessage(message.role, message.html);
  if (message.type === "history") {
    messages.replaceChildren(welcome);
    for (const item of message.messages) appendMessage(item.role, item.html);
    welcome.hidden = message.messages.length > 0;
  }
  if (message.type === "cleared") {
    messages.replaceChildren(welcome);
    welcome.hidden = false;
    status.textContent = "";
  }
  if (message.type === "busy") {
    busy = message.value;
    sendButton.disabled = busy;
    status.textContent = busy ? "Thinking…" : "";
  }
  if (message.type === "error") {
    status.textContent = message.text;
    status.classList.add("error");
  } else if (message.type === "busy") {
    status.classList.remove("error");
  }
});

vscode.postMessage({ type: "ready" });
