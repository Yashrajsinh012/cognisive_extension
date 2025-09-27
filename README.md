#Cognisive VS Code Extension

**Cognisive** is a Visual Studio Code extension that helps developers write secure code by detecting real-time security vulnerabilities and providing actionable guidance using **Retrieval-Augmented Generation (RAG)** technology.

---

## Features

-  **Real-time Security Detection**: Automatically scans code for common security issues as you type.
-  **Secure Coding Suggestions**: Offers recommendations to fix identified vulnerabilities.
- **Customizable Rules**: Users can define and extend security rules to fit their project needs.
-  **VS Code Integration**: Seamlessly works within the VS Code environment for smooth developer experience.

---

## Project Structure

cognisive_extension/
├── .vscode/ # VS Code workspace settings
├── rules/ # Security rules definitions
├── src/ # Source code of the extension
├── test/ # Unit and integration tests
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── PROJECT_STRUCTURE.md
├── README.md
├── eslint.config.mjs # ESLint configuration
├── package-lock.json
├── package.json # Project dependencies and scripts
├── tsconfig.json # TypeScript configuration
├── vsc-extension-quickstart.md

## Installation

1. Clone this repository

```bash
git clone https://github.com/Yashrajsinh012/cognisive_extension.git
cd cognisive_extension
```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Compile the extension:
   ```bash
   npm run compile
   ```
4. Press F5 to run the extension in a new Extension Development Host window

## Configuration

### Environment Variables
Create a `.env` file in the project root:
```env
GROQ_API_KEY=your_groq_api_key_here
```

### Secure Coding Knowledge Base
The extension uses two knowledge files:
- `rules/secure_coding_kb.txt` - Comprehensive secure coding guidelines
- `rules/hardcoded-secrets.yml` - Semgrep rules for vulnerability detection

## Usage

### Security Scanning
The extension automatically scans files on save and provides:
- Real-time vulnerability detection
- Inline error highlighting
- QuickFix suggestions
- Detailed security guidance

### Prompt Enhancement
Add comments to your code to get AI-enhanced security prompts:
```javascript
// PROMPT: Write a login function
// ENHANCED_PROMPT: [AI-generated secure implementation guidance]
```

### Supported File Types
- JavaScript (.js)
- TypeScript (.ts)
- JSON (package.json)
- JSX/TSX files

## Security Rules

### Hardcoded Secrets
Detects patterns like:
```javascript
const apiKey = "sk-1234567890abcdef";
const password = 'hardcoded_password';
const config = {
    secret: "api_secret_here"
};
```

### Missing Authorization
Identifies functions without proper auth checks:
```javascript
function getUser(userId) {
    // Missing authorization - will be flagged
    return database.getUser(userId);
}
```

### SSRF Vulnerabilities
Detects user-controlled URLs in HTTP requests:
```javascript
fetch(req.query.url); // Will be flagged
axios.get(req.params.apiUrl); // Will be flagged
```

### Vulnerable Dependencies
Scans package.json for known vulnerabilities:
```json
{
  "dependencies": {
    "lodash": "4.17.5", // CVE-2021-23337
    "axios": "0.21.0"   // CVE-2021-3749
  }
}
```

## Development

### Project Structure
```
src/
├── extension.ts          # Main extension logic
├── test/
│   ├── extension.test.js
│   └── extension.test.ts
rules/
├── secure_coding_kb.txt  # Knowledge base
└── hardcoded-secrets.yml # Semgrep rules
```

### Building
```bash
npm run compile
```

### Testing
```bash
npm test
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

