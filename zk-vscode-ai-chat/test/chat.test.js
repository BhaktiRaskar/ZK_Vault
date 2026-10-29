"use strict";

const assert = require("node:assert/strict");
const Module = require("node:module");
const test = require("node:test");

const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === "vscode") {
    return {
      workspace: { getConfiguration: () => ({ get: (_key, fallback) => fallback }) }
    };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const { ChatViewProvider, markdown } = require("../extension");
Module._load = originalLoad;

const provider = new ChatViewProvider({ extensionUri: {}, extensionPath: "" });

test("parses supported slash commands and preserves their prompt", () => {
  assert.deepEqual(provider.parseSlashCommand("/fix null access"), {
    command: "fix",
    text: "null access"
  });
  assert.deepEqual(provider.parseSlashCommand("explain this"), {
    command: "",
    text: "explain this"
  });
});

test("builds a contextual request for a slash action", () => {
  const content = provider.createUserContent("", "Selected code:\n```js\nconst a = 1;\n```", "explain");
  assert.match(content, /Explain the following code/);
  assert.match(content, /const a = 1/);
});

test("renders code fences with highlighted code and copy controls", () => {
  const html = markdown.render("```js\nconst answer = 42;\n```");
  assert.match(html, /class="copy-code"/);
  assert.match(html, /hljs/);
  assert.match(html, /language-js/);
});

test("does not render raw HTML from an assistant response", () => {
  const html = markdown.render("<script>alert(1)</script>");
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
});
