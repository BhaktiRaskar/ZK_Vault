/**
 * config.js  –  Frontend API Configuration
 * ==========================================
 * Change API_BASE_URL to point at your deployed backend.
 *
 * Local development : http://127.0.0.1:5000 (Flask API)
 * Production        : your deployed backend origin, e.g. https://api.example.com
 *
 * This file is the ONLY place you need to change when deploying.
 * Never hardcode localhost in app.js.
 */

const CONFIG = {
  // Must be the Flask backend origin, not the frontend's origin. No trailing slash.
  // This local URL matches the Flask app's default port.
  API_BASE_URL: "https://zk-vault-rf59.onrender.com/",
};
