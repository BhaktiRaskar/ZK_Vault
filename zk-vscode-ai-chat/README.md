# VS Code AI Chat Assistant

A context-aware chat extension that runs in the VS Code Activity Bar. API keys are stored in VS Code SecretStorage and are not written to workspace settings.

## Features

- Sidebar chat with Markdown rendering, syntax-highlighted code fences, and one-click code copying.
- Optional editor context: selected text, or the current file when no text is selected.
- `/explain`, `/fix`, and `/refactor` commands in chat, plus matching Command Palette actions.
- OpenAI, Gemini, Groq, and Ollama providers.

## Requirements

- VS Code 1.85 or later.
- Node.js 18 or later for running the extension tests.
- An API key for OpenAI, Gemini, or Groq. Ollama can run locally without a key.

## Run from source

1. Open the `zk-vscode-ai-chat` folder in VS Code.
2. Run `npm install` in the extension folder.
3. Press `F5` to start the Extension Development Host.
4. Open the **AI Chat** Activity Bar view.
5. Run **AI Chat: Set API Key** from the Command Palette for the selected provider.

Configure `zkAiChat.provider` and `zkAiChat.model` in VS Code Settings. The initial model defaults to `gpt-4o-mini`; select a model supported by your provider (for example, a Gemini model for Gemini or an installed model name for Ollama). For Ollama, configure `zkAiChat.ollamaBaseUrl` if it is not listening at its default local address.

## Privacy

When editor context is enabled, the active selection or open file is sent to the configured AI provider with your prompt. Context is limited by `zkAiChat.maxContextCharacters` (20,000 by default). Turn off `zkAiChat.includeCurrentFile` to omit editor context. Review provider privacy and retention policies before sending sensitive source code.

Provider API keys are saved using VS Code's SecretStorage API. Ollama requests are sent to the configured local server.
