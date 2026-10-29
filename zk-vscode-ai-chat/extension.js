"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vscode = require("vscode");
const MarkdownIt = require("markdown-it");
const hljs = require("highlight.js");

const SECRET_PREFIX = "zkAiChat.apiKey.";
const COMMANDS = {
  explain: "Explain the following code clearly, including its purpose and important details.",
  fix: "Find and fix the issue in the following code. Explain the cause and provide the corrected code.",
  refactor: "Refactor the following code for clarity and maintainability while preserving its behavior."
};

const markdown = new MarkdownIt({
  html: false,
  linkify: false,
  breaks: true,
  highlight(code, language) {
    if (language && hljs.getLanguage(language)) {
      return hljs.highlight(code, { language }).value;
    }
    return hljs.highlightAuto(code).value;
  }
});

markdown.renderer.rules.fence = (tokens, index) => {
  const token = tokens[index];
  const language = token.info.trim().split(/\s+/, 1)[0] || "code";
  const highlighted = markdown.options.highlight(token.content, language);
  const body = highlighted || markdown.utils.escapeHtml(token.content);
  return `<div class="code-block"><div class="code-toolbar"><span>${markdown.utils.escapeHtml(language)}</span><button class="copy-code" type="button" aria-label="Copy code">Copy</button></div><pre><code class="hljs language-${markdown.utils.escapeHtml(language)}">${body}</code></pre></div>`;
};

class ChatViewProvider {
  constructor(context) {
    this.context = context;
    this.view = undefined;
    this.history = [];
    this.busy = false;
  }

  resolveWebviewView(view) {
    this.view = view;
    view.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this.context.extensionUri, "media")]
    };
    view.webview.html = this.getHtml(view.webview);
    view.webview.onDidReceiveMessage(message => {
      if (message?.type === "send" && typeof message.text === "string") {
        void this.sendMessage(message.text);
      } else if (message?.type === "clear") {
        this.history = [];
        this.post({ type: "cleared" });
      } else if (message?.type === "copy" && typeof message.text === "string") {
        void vscode.env.clipboard.writeText(message.text);
      } else if (message?.type === "ready") {
        this.post({ type: "history", messages: this.history.map(({ role, content }) => ({ role, html: markdown.render(content) })) });
      }
    });
  }

  post(message) {
    if (this.view) {
      void this.view.webview.postMessage(message);
    }
  }

  getHtml(webview) {
    const nonce = crypto.randomBytes(16).toString("base64");
    const styleUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, "media", "chat.css"));
    const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, "media", "chat.js"));
    const template = fs.readFileSync(path.join(this.context.extensionPath, "media", "chat.html"), "utf8");
    return template
      .replaceAll("{{cspSource}}", webview.cspSource)
      .replaceAll("{{nonce}}", nonce)
      .replaceAll("{{styleUri}}", styleUri.toString())
      .replaceAll("{{scriptUri}}", scriptUri.toString());
  }

  async sendMessage(rawText) {
    const text = rawText.trim();
    if (!text || this.busy) return;

    const provider = this.getConfig().get("provider", "openai");
    const key = await this.context.secrets.get(SECRET_PREFIX + provider);
    if (provider !== "ollama" && !key) {
      this.post({ type: "error", text: `Set an API key for ${provider} first using “AI Chat: Set API Key”.` });
      return;
    }

    const editorContext = this.getEditorContext();
    const parsed = this.parseSlashCommand(text);
    const userContent = this.createUserContent(parsed.text, editorContext, parsed.command);
    this.history.push({ role: "user", content: userContent });
    this.post({ type: "message", role: "user", html: markdown.render(text) });
    this.busy = true;
    this.post({ type: "busy", value: true });

    try {
      const answer = await this.requestCompletion(provider, key, this.history);
      this.history.push({ role: "assistant", content: answer });
      this.post({ type: "message", role: "assistant", html: markdown.render(answer) });
    } catch (error) {
      this.history.pop();
      this.post({ type: "error", text: error.message || "The AI request failed." });
    } finally {
      this.busy = false;
      this.post({ type: "busy", value: false });
    }
  }

  getConfig() {
    return vscode.workspace.getConfiguration("zkAiChat");
  }

  getEditorContext() {
    if (!this.getConfig().get("includeCurrentFile", true)) return "";
    const editor = vscode.window.activeTextEditor;
    if (!editor) return "";
    const selection = editor.selection;
    const text = selection.isEmpty
      ? editor.document.getText()
      : editor.document.getText(selection);
    const limit = this.getConfig().get("maxContextCharacters", 20000);
    const boundedText = text.length > limit
      ? `${text.slice(0, limit)}\n\n[Context truncated at ${limit} characters.]`
      : text;
    const label = selection.isEmpty ? "Current file" : "Selected code";
    return `${label}: ${editor.document.fileName}\n\`\`\`${editor.document.languageId}\n${boundedText}\n\`\`\``;
  }

  parseSlashCommand(text) {
    const match = text.match(/^\/(explain|fix|refactor)(?:\s+([\s\S]*))?$/i);
    if (!match) return { command: "", text };
    const command = match[1].toLowerCase();
    return { command, text: match[2] || "" };
  }

  createUserContent(text, editorContext, command) {
    const instruction = command ? `${COMMANDS[command]}\n\n` : "";
    const question = text || (editorContext ? "Use the requested action on this code." : "");
    if (!question && !editorContext) return "";
    return `${instruction}${question}${editorContext ? `\n\n${editorContext}` : ""}`;
  }

  async requestCompletion(provider, key, messages) {
    const model = this.getConfig().get("model", "gpt-4o-mini");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 90000);
    try {
      if (provider === "gemini") {
        return await this.requestGemini(model, key, messages, controller.signal);
      }
      return await this.requestOpenAiCompatible(provider, model, key, messages, controller.signal);
    } finally {
      clearTimeout(timeout);
    }
  }

  async requestOpenAiCompatible(provider, model, key, messages, signal) {
    const baseUrls = {
      openai: "https://api.openai.com/v1",
      groq: "https://api.groq.com/openai/v1",
      ollama: this.getConfig().get("ollamaBaseUrl", "http://localhost:11434").replace(/\/+$/, "") + "/v1"
    };
    const headers = { "Content-Type": "application/json" };
    if (key) headers.Authorization = `Bearer ${key}`;
    const response = await fetch(`${baseUrls[provider]}/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify({ model, messages: messages.map(({ role, content }) => ({ role, content })) }),
      signal
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error?.message || `Provider request failed (${response.status}).`);
    const answer = data.choices?.[0]?.message?.content;
    if (typeof answer !== "string") throw new Error("The provider returned an empty or unsupported response.");
    return answer;
  }

  async requestGemini(model, key, messages, signal) {
    const system = messages.filter(message => message.role === "system").map(message => message.content).join("\n\n");
    const contents = messages
      .filter(message => message.role !== "system")
      .map(message => ({
        role: message.role === "assistant" ? "model" : "user",
        parts: [{ text: message.content }]
      }));
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(key)}`;
    const body = { contents };
    if (system) body.systemInstruction = { parts: [{ text: system }] };
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error?.message || `Gemini request failed (${response.status}).`);
    const answer = data.candidates?.[0]?.content?.parts?.map(part => part.text || "").join("");
    if (!answer) throw new Error("Gemini returned an empty or unsupported response.");
    return answer;
  }
}

function activate(context) {
  const provider = new ChatViewProvider(context);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("zkAiChat.chatView", provider),
    vscode.commands.registerCommand("zkAiChat.open", async () => {
      await vscode.commands.executeCommand("workbench.view.extension.zkAiChat");
    }),
    vscode.commands.registerCommand("zkAiChat.setApiKey", () => setApiKey(context)),
    vscode.commands.registerCommand("zkAiChat.explainSelection", () => sendQuickAction(provider, "explain")),
    vscode.commands.registerCommand("zkAiChat.fixSelection", () => sendQuickAction(provider, "fix")),
    vscode.commands.registerCommand("zkAiChat.refactorSelection", () => sendQuickAction(provider, "refactor"))
  );
}

async function setApiKey(context) {
  const provider = vscode.workspace.getConfiguration("zkAiChat").get("provider", "openai");
  const key = await vscode.window.showInputBox({
    prompt: `Enter the API key for ${provider}. It is stored in VS Code SecretStorage.`,
    password: true,
    ignoreFocusOut: true
  });
  if (key === undefined) return;
  if (!key.trim() && provider !== "ollama") {
    vscode.window.showErrorMessage("The API key cannot be empty.");
    return;
  }
  if (key.trim()) {
    await context.secrets.store(SECRET_PREFIX + provider, key.trim());
  } else {
    await context.secrets.delete(SECRET_PREFIX + provider);
  }
  vscode.window.showInformationMessage(provider === "ollama" && !key.trim()
    ? "Ollama API key cleared. Ollama can run without a key."
    : `API key saved securely for ${provider}.`);
}

async function sendQuickAction(provider, action) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage("Open a file or select code before using this action.");
    return;
  }
  await vscode.commands.executeCommand("workbench.view.extension.zkAiChat");
  const selection = editor.selection;
  if (selection.isEmpty) {
    vscode.window.showInformationMessage("Select code to send a quick action, or use the chat input.");
    return;
  }
  void provider.sendMessage(`/${action}`);
}

function deactivate() {}

module.exports = { activate, deactivate, ChatViewProvider, markdown };
