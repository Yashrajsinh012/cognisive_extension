import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as dotenv from 'dotenv';
import fetch from 'node-fetch'; // Assumes node-fetch is available in the environment

// Load environment variables from .env at workspace root
dotenv.config({ path: path.join(__dirname, '..', '.env') });

const GROQ_API_KEY = process.env.GROQ_API_KEY;

if (!GROQ_API_KEY) {
    vscode.window.showErrorMessage('coginivise: GROQ_API_KEY is missing in .env. Please add it.');
    console.error('coginivise: GROQ_API_KEY is missing in .env');
}

let diagnosticCollection: vscode.DiagnosticCollection | undefined;

// Load RAG KB
let secureCodingKB = '';
let hardcodedSecretsYml = '';
try {
    const kbPath = path.join(__dirname, '..', 'rules', 'secure_coding_kb.txt');
    // Using fs.readFileSync in activate is usually okay for extensions loading their own files
    secureCodingKB = fs.readFileSync(kbPath, 'utf8');
    console.log('coginivise: loaded secure_coding_kb.txt, length:', secureCodingKB.length);
} catch (err) {
    console.warn('coginivise: secure_coding_kb.txt not found in rules/, continuing without KB');
}

try {
    const ymlPath = path.join(__dirname, '..', 'rules', 'hardcoded-secrets.yml');
    hardcodedSecretsYml = fs.readFileSync(ymlPath, 'utf8');
    console.log('coginivise: loaded hardcoded-secrets.yml, length:', hardcodedSecretsYml.length);
} catch (err) {
    console.warn('coginivise: hardcoded-secrets.yml not found in rules/, continuing without YAML');
}


/* ------------------- Activate / Deactivate ------------------- */
export function activate(context: vscode.ExtensionContext) {
    // Use the name 'coginivise' for the unified diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('coginivise');
    context.subscriptions.push(diagnosticCollection);

    // 1️⃣ Auto scan on document save (for JS/TS and package.json)
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(doc => {
            try {
                if (isJavascriptDoc(doc) || doc.fileName.endsWith('package.json')) {
                    runSecurityScan(doc);
                }
            } catch (e) {
                console.error('Scan on save error', e);
            }
        })
    );

    // 2️⃣ Enhance prompts on document change
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(event => {
            try {
                // Use the async LLM-enhanced version
                detectAndEnhancePrompts(event.document);
            } catch (e) {
                console.error('Prompt enhancement error', e);
            }
        })
    );

    // 3️⃣ Manual scan command (Renamed from SafePrompt.runScan to coginivise.runScan)
    context.subscriptions.push(
        vscode.commands.registerCommand('coginivise.runScan', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) runSecurityScan(editor.document);
            else vscode.window.showInformationMessage('Open a JS/TS or package.json file to scan.');
        })
    );

    // 4️⃣ QuickFix provider (Using the more comprehensive SecurityCodeActionProvider)
    const provider = new SecurityCodeActionProvider();
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            ['javascript', 'javascriptreact', 'typescript', 'typescriptreact', 'json'],
            provider,
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );

    // Initial scan for active file
    const active = vscode.window.activeTextEditor;
    if (active && (isJavascriptDoc(active.document) || active.document.fileName.endsWith('package.json'))) {
        runSecurityScan(active.document);
    }

    console.log('✅ coginivise extension activated (Merged)');
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.clear();
        diagnosticCollection.dispose();
    }
}

/* --------------------------- Prompt detection/enhancement (LLM and Local Fallback) --------------------------- */

// Function signature made async to support Groq API call
export async function detectAndEnhancePrompts(document: vscode.TextDocument) {
    const text = document.getText();
    const lines = text.split(/\r?\n/);
    const edit = new vscode.WorkspaceEdit();
    let madeEdit = false;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const m = line.match(/^\s*\/\/\s*PROMPT\s*:\s*(.+)$/i);
        if (m) {
            const userPrompt = m[1].trim();
            const nextLine = lines[i + 1] || '';

            // Skip if ENHANCED_PROMPT already exists
            if (!nextLine.match(/^\s*\/\/\s*ENHANCED_PROMPT\s*:/i)) {
                try {
                    // Call the LLM-enhanced prompt via Groq REST (will fallback if API fails)
                    const enhanced = await generateEnhancedPrompt(userPrompt);

                    // Insert the enhanced prompt in the next line
                    const insertion = `// ENHANCED_PROMPT: ${enhanced}`;
                    edit.insert(document.uri, new vscode.Position(i + 1, 0), insertion + '\n');
                    madeEdit = true;
                } catch (err) {
                    console.error('coginivise: Failed to generate enhanced prompt', err);
                    // No need for secondary local fallback here, as it's handled within generateEnhancedPrompt
                }
            }
        }
    }

    if (madeEdit) {
        vscode.workspace.applyEdit(edit).then(
            (applied) => {
                if (applied) {
                    vscode.window.showInformationMessage('coginivise: Enhanced prompt(s) inserted.');
                } else {
                    console.error('coginivise: Edit was not applied.');
                }
            },
            (err) => {
                console.error('coginivise: Failed to apply edits', err);
            }
        );
    }
}

/* --------------------------- LLM Enhanced Prompt (with RAG) --------------------------- */
async function generateEnhancedPrompt(userPrompt: string): Promise<string> {
    if (!GROQ_API_KEY) return generateLocalEnhancedPrompt(userPrompt);

    // Build RAG context from local rule files
    const ragContext = buildRagContext(userPrompt);

    // System Instruction to guide the model's behavior
    const systemInstruction = `
        You are a secure coding assistant acting as a rules-grounded prompt enhancer.
        Use ONLY the provided Security Reference Excerpts to inject concrete, actionable
        security requirements into the developer's prompt, so that any downstream LLM
        will generate code that follows these rules.

        Required outcomes for the enhanced prompt:
        - Enforce input validation and output encoding where relevant.
        - Prohibit hardcoded credentials; require use of environment variables or secret managers.
        - Require parameterized queries and safe crypto primitives where applicable.
        - Require explicit authentication and authorization checks for sensitive operations.
        - Prefer maintained, non-deprecated libraries and safe defaults.
        - Avoid logging secrets or sensitive PII.

        Output requirements:
        - Return ONE concise natural-language instruction paragraph suitable as a system/user prompt
          for another LLM. No code blocks, no lists, no extra commentary.
        - Do not invent rules beyond the provided excerpts; ground your guidance in them.
    `;

    // Combine user prompt and RAG context (if available)
    const fullUserContent = `Developer Prompt: "${userPrompt}"\n\nSecurity Reference Excerpts:\n${ragContext}`;


    try {
        const res = await fetch('https://api.groq.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${GROQ_API_KEY}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                model: 'llama-3.1-8b-instant', // Use a known working Groq model
                messages: [
                    { role: "system", content: systemInstruction.trim() },
                    { role: "user", content: fullUserContent.trim() }
                ],
                max_tokens: 300,
                temperature: 0.2
            })
        });

        const data = await res.json();
        // console.log('Groq API raw response:', data); // Debugging line

        if (res.status !== 200) {
            console.error('Groq API returned an error status:', res.status, data);
            // Fallback to local enhancement if API fails
            return generateLocalEnhancedPrompt(userPrompt);
        }

        // Standard Groq/OpenAI chat completion extraction
        if (data.choices && data.choices.length > 0 && data.choices[0].message && data.choices[0].message.content) {
            const content = data.choices[0].message.content.trim();
            console.log('coginivise: Successfully extracted enhanced prompt.');
            // Clean up potential quotes and trim
            return content.replace(/^(["'`\s]*)/, '').replace(/(["'`\s]*)$/, '').trim();
        }

        // Fallback if structure is unexpected
        console.warn('coginivise: Unexpected API response structure, falling back to local enhancement');
        return generateLocalEnhancedPrompt(userPrompt);

    } catch (err) {
        console.error('coginivise: Groq API call failed', err);
        // Fallback to local enhancement on any error
        return generateLocalEnhancedPrompt(userPrompt);
    }
}

// Local fallback enhancement when API fails (Combines logic from both original files)
function generateLocalEnhancedPrompt(userPrompt: string): string {
    // Note: The logic here is a *simplified* version of the LLM/RAG one, serving as a backup.
    let enhanced = userPrompt;
    const lower = userPrompt.toLowerCase();

    // Core security requirements (from SafePrompt logic)
    let baseRequirements = '';
    if (lower.includes('login') || lower.includes('auth')) {
        baseRequirements += ', include robust input validation, role-based authorization, and CSRF protection';
    } else {
        baseRequirements += ', include input validation, and role-based authorization';
    }

    // Hardcoded secrets are crucial, so explicitly add the requirement
    if (!lower.includes('no hardcoded') && !lower.includes('secret manager') && !lower.includes('env var')) {
        baseRequirements += ', do not include hardcoded API keys, passwords, or secrets; use environment variables or a secret manager instead';
    }

    enhanced += baseRequirements;

    // Add RAG context for developer awareness (from coginivise logic)
    const ragContext = buildRagContext(userPrompt);
    if (ragContext) {
        // Only append a small mention of the context to keep it concise
        const contextSummary = ragContext.split('\n').filter(line => line.trim().length > 0).slice(0, 3).join(' ').substring(0, 200);
        enhanced += `. Also, consider these guidelines: ${contextSummary}...`;
    }

    return enhanced.trim();
}

// Simple section extractor for markdown-ish KB files
function extractSection(content: string, sectionHeading: string): string {
    try {
        const re = new RegExp(`(^|\n)##\\s+${sectionHeading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[\\s\\S]*?(?=\\n##\\s+|$)`, 'i');
        const m = content.match(re);
        return m ? m[0].trim() : '';
    } catch {
        return '';
    }
}

// Build a small RAG context string grounded in our local rule files
function buildRagContext(userPrompt: string): string {
    const parts: string[] = [];

    const p = userPrompt || '';
    const wantsAuth = /(auth|login|role|permission|oauth|jwt)/i.test(p);
    const wantsSecrets = /(secret|api\s*key|apikey|token|credential|password)/i.test(p);
    const wantsDB = /(sql|query|database|postgres|mysql|sqlite)/i.test(p);

    if (secureCodingKB) {
        if (wantsSecrets) {
            parts.push(extractSection(secureCodingKB, 'Hardcoded Secrets'));
        }
        if (wantsAuth) {
            parts.push(extractSection(secureCodingKB, 'Missing Authorization Checks'));
            parts.push(extractSection(secureCodingKB, 'Authentication'));
        }
        if (wantsDB) {
            parts.push(extractSection(secureCodingKB, 'SQL Injection'));
        }
        // Always include generic guidelines as a fallback
        parts.push(extractSection(secureCodingKB, 'Additional Secure Coding Guidelines'));
    }

    if (hardcodedSecretsYml && wantsSecrets) {
        // Include a small trimmed excerpt of the YAML rules for secrets
        parts.push('--- hardcoded-secrets.yml excerpt ---');
        parts.push(hardcodedSecretsYml.substring(0, 1200));
    }

    const joined = parts.filter(Boolean).join('\n\n');
    // Cap total length to stay within context limits
    return joined.substring(0, 3000);
}


/* ------------------- Security Scan (Semgrep + Enhanced Regex Fallback) ------------------- */

function isJavascriptDoc(document: vscode.TextDocument): boolean {
    return ['javascript', 'javascriptreact', 'typescript', 'typescriptreact'].includes(document.languageId);
}

function runSecurityScan(document: vscode.TextDocument) {
    if (!diagnosticCollection) return;
    diagnosticCollection.delete(document.uri);

    if (document.fileName.endsWith('package.json')) {
        scanDependencies(document);
        return;
    }

    const filePath = document.fileName;
    // Use the workspace/rules path logic from coginivise
    const extFolder = vscode.workspace.getWorkspaceFolder(document.uri)
        ? vscode.workspace.getWorkspaceFolder(document.uri)!.uri.fsPath
        : path.dirname(filePath);
    // Use 'rules.yml' from the coginivise rule structure. The original SafePrompt used 'semgrep_rules/security-rules.yml'
    const rulesPath = path.join(extFolder, 'rules', 'rules.yml');

    cp.exec('semgrep --version', err => {
        if (err) {
            console.warn('⚠️ Semgrep not found — using comprehensive fallback regex scan.');
            diagnosticCollection!.set(document.uri, findIssuesWithRegex(document));
            return;
        }

        const cmd = `semgrep --json --config ${quote(rulesPath)} ${quote(filePath)}`;
        cp.exec(cmd, { maxBuffer: 10 * 1024 * 1024 }, (err2, stdout) => {
            if (err2 && !stdout) {
                console.error('Semgrep run error:', err2);
                diagnosticCollection!.set(document.uri, findIssuesWithRegex(document));
                return;
            }
            try {
                const data = JSON.parse(stdout);
                // Use the better semgrepJsonToDiagnostics from the SafePrompt file
                const semgrepDiags = semgrepJsonToDiagnostics(data, document);
                const regexDiags = findIssuesWithRegex(document);
                diagnosticCollection!.set(document.uri, semgrepDiags.concat(regexDiags));
            } catch (e) {
                console.error('Error parsing semgrep output, fallback to regex', e);
                diagnosticCollection!.set(document.uri, findIssuesWithRegex(document));
            }
        });
    });
}

function quote(s: string): string {
    return s.includes(' ') ? `"${s}"` : s;
}

/* ------------------- Semgrep Output to Diagnostics (SafePrompt's superior version) --------------------------- */
function semgrepJsonToDiagnostics(data: any, document: vscode.TextDocument): vscode.Diagnostic[] {
    const diags: vscode.Diagnostic[] = [];
    if (!data || !Array.isArray(data.results)) return diags;

    for (const r of data.results) {
        try {
            const start = r.start || (r.extra && r.extra.start);
            const end = r.end || (r.extra && r.extra.end);
            const message = r.extra?.message || r.message || 'Security issue';
            // Use severity levels from Semgrep if available
            const severity = r.extra?.severity?.toLowerCase() || 'warning';
            const severityLevel = severity === 'error'
                ? vscode.DiagnosticSeverity.Error
                : severity === 'warning'
                    ? vscode.DiagnosticSeverity.Warning
                    : vscode.DiagnosticSeverity.Information;

            if (start && end) {
                const range = new vscode.Range(
                    start.line - 1, Math.max(0, (start.col || 1) - 1),
                    end.line - 1, Math.max(0, (end.col || 1) - 1)
                );
                // Use check_id in the message for context
                const diag = new vscode.Diagnostic(range, `[${r.check_id}] ${message}`, severityLevel);
                diag.code = r.check_id || 'coginivise.unknown';
                diags.push(diag);
            }
        } catch (e) {
            console.error('Error converting semgrep result', e);
        }
    }

    return diags;
}


/* --------------------------- Regex Fallback Scanner (Merge of both) --------------------------- */
function findIssuesWithRegex(document: vscode.TextDocument): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];
    const lines = document.getText().split(/\r?\n/);

    // 🔐 Hardcoded secrets/passwords detection (Using SafePrompt's more precise regex/range logic)
    const secretRegex = new RegExp(
        '(api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|cred)\\s*[:=]\\s*([\'"`])([^\'"`]+)\\2',
        'i'
    );

    lines.forEach((line, i) => {
        const m = secretRegex.exec(line);
        if (m && typeof m.index === 'number') {
            // SafePrompt's logic for finding the exact quoted literal range
            const matchStart = m.index;
            const quoteChar = m[2];
            const openQuoteIdx = line.indexOf(quoteChar, matchStart);
            const closeQuoteIdx = openQuoteIdx >= 0 ? line.indexOf(quoteChar, openQuoteIdx + 1) : -1;

            let startCol = 0;
            let endCol = line.length;
            if (openQuoteIdx >= 0 && closeQuoteIdx >= 0) {
                startCol = openQuoteIdx;
                endCol = closeQuoteIdx + 1; // include closing quote
            } else {
                const value = m[3];
                const valuePos = line.indexOf(value, matchStart);
                if (valuePos >= 0) {
                    startCol = valuePos;
                    endCol = valuePos + value.length;
                } else {
                    startCol = matchStart;
                    endCol = matchStart + m[0].length;
                }
            }

            const range = new vscode.Range(i, startCol, i, endCol);
            const diag = new vscode.Diagnostic(
                range,
                'Hardcoded secret or password detected. Move this to environment variables or a secret manager.',
                vscode.DiagnosticSeverity.Warning
            );
            diag.code = 'coginivise.hardcoded_secret'; // Use 'coginivise' prefix
            diagnostics.push(diag);
        }
    });

    // 🛑 Missing authorization detection (Using coginivise's more comprehensive version)
    const authIssues = findMissingAuthorization(document);
    diagnostics.push(...authIssues);

    // 🌐 SSRF vulnerabilities detection (From coginivise)
    const ssrfIssues = findSSRFVulnerabilities(document);
    diagnostics.push(...ssrfIssues);


    return diagnostics;
}

// Detect functions that may lack authorization checks (From coginivise)
function findMissingAuthorization(document: vscode.TextDocument): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];
    const text = document.getText();
    const lines = text.split(/\r?\n/);

    // Patterns for sensitive functions that should have authorization
    const sensitiveFunctionPatterns = [
        /function\s+(login|authenticate|auth)\s*\(/i,
        /function\s+(getUser|getUserData|getUserInfo|fetchUser|deleteUser|removeUser|updateUser|modifyUser)\s*\(/i,
        /function\s+(admin|root|superuser|delete|remove|destroy|update|modify|edit)\w*\s*\(/i,
        /const\s+(login|authenticate|auth)\s*=\s*\(/i,
        /const\s+(getUser|getUserData|getUserInfo|fetchUser|deleteUser|removeUser|updateUser|modifyUser)\s*=\s*\(/i,
        /const\s+(admin|root|superuser|delete|remove|destroy|update|modify|edit)\w*\s*=\s*\(/i,
        /(login|authenticate|auth|getUser|deleteUser|admin)\w*\s*:\s*function/i,
    ];

    // Authorization check patterns
    const authCheckPatterns = [
        /isAuthenticated/i, /isAuthorized/i, /hasRole/i, /hasPermission/i,
        /checkAuth/i, /verifyToken/i, /validateUser/i, /user\.role/i,
        /req\.user/i, /session\.user/i, /jwt\.verify/i, /auth\.verify/i,
        /middleware.*auth/i, /requireAuth/i, /requireRole/i, /requirePermission/i
    ];

    lines.forEach((line, lineIndex) => {
        for (const pattern of sensitiveFunctionPatterns) {
            const match = line.match(pattern);
            if (match) {
                // Function name extraction is complex, fallback to a simple name or 'function'
                const functionName = match[1] || match[0].split(/\s+/)[1] || 'function';

                let hasAuthCheck = false;
                const functionStartLine = lineIndex;
                const searchEndLine = Math.min(lineIndex + 20, lines.length);

                for (let i = functionStartLine; i < searchEndLine; i++) {
                    const currentLine = lines[i];

                    if (i > functionStartLine && /^\s*(function|const|let|var|class)\s+\w+/.test(currentLine)) {
                        break;
                    }

                    for (const authPattern of authCheckPatterns) {
                        if (authPattern.test(currentLine)) {
                            hasAuthCheck = true;
                            break;
                        }
                    }

                    if (hasAuthCheck) break;
                }

                if (!hasAuthCheck) {
                    const range = new vscode.Range(lineIndex, 0, lineIndex, line.length);
                    const diag = new vscode.Diagnostic(
                        range,
                        `Function '${functionName}' may lack authorization checks. Add role validation.`,
                        vscode.DiagnosticSeverity.Warning
                    );
                    diag.code = 'coginivise.missing_authorization';
                    diagnostics.push(diag);
                }
            }
        }
    });

    return diagnostics;
}

// Detect SSRF vulnerabilities (From coginivise)
function findSSRFVulnerabilities(document: vscode.TextDocument): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];
    const text = document.getText();
    const lines = text.split(/\r?\n/);

    // SSRF patterns for HTTP requests with user-controlled URLs
    const ssrfPatterns = [
        // Using concise generic patterns to cover most cases
        /fetch\s*\(\s*[^)]*req\.[^)]*\)/i,
        /axios\.(get|post|put|delete|patch|head|options)\s*\(\s*[^)]*req\.[^)]*\)/i,
        /request\s*\(\s*[^)]*req\.[^)]*\)/i,
        /https?\.(get|post|put|delete|patch|head|options)\s*\(\s*[^)]*req\.[^)]*\)/i,
        /\$\.(get|post|ajax)\s*\(\s*[^)]*req\.[^)]*\)/i
    ];

    lines.forEach((line, lineIndex) => {
        for (const pattern of ssrfPatterns) {
            const match = line.match(pattern);
            if (match) {
                const range = new vscode.Range(lineIndex, 0, lineIndex, line.length);
                const diag = new vscode.Diagnostic(
                    range,
                    'SSRF vulnerability: HTTP request with user-controlled input. Validate URL origin and use allowlist of permitted domains.',
                    vscode.DiagnosticSeverity.Error
                );
                diag.code = 'coginivise.ssrf_vulnerability';
                diagnostics.push(diag);
            }
        }
    });

    return diagnostics;
}


/* ------------------- Scan Dependencies (From coginivise) ------------------- */
function scanDependencies(document: vscode.TextDocument) {
    const diagnostics: vscode.Diagnostic[] = [];
    try {
        const content = document.getText();
        const json = JSON.parse(content);
        const dependencies = { ...json.dependencies, ...json.devDependencies };

        // Check for hardcoded secrets in package.json
        const secretIssues = findSecretsInPackageJson(content);
        diagnostics.push(...secretIssues);

        // Check for outdated/vulnerable dependencies
        Object.entries(dependencies).forEach(([pkg, version]) => {
            if (typeof version === 'string') {
                const line = content.split(/\r?\n/).findIndex(l => l.includes(`"${pkg}"`));
                if (line >= 0) {
                    const range = new vscode.Range(line, 0, line, content.split(/\r?\n/)[line].length);
                    const vulnIssues = checkDependencyVulnerabilities(pkg, version, range);
                    diagnostics.push(...vulnIssues);
                }
            }
        });

    } catch (e) {
        console.error('Dependency scan error', e);
    }
    diagnosticCollection?.set(document.uri, diagnostics);
}

// Check for hardcoded secrets in package.json (From coginivise)
function findSecretsInPackageJson(content: string): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];
    const lines = content.split(/\r?\n/);

    const secretPatterns = [
        /(api[_-]?key|apikey|secret|token|password|pwd|credential)\s*[:=]\s*['"`]([^'"`]+)['"`]/i,
        /['"`](sk-[a-zA-Z0-9]{20,})['"`]/g,
        /['"`](pk_[a-zA-Z0-9]{20,})['"`]/g,
        /['"`]([a-zA-Z0-9]{32,})['"`]/g
    ];

    lines.forEach((line, i) => {
        for (const pattern of secretPatterns) {
            const matches = line.matchAll(pattern);
            for (const match of matches) {
                const secretValue = match[1] || match[0];
                if (secretValue.length < 20 || /^[\d\.\-\^~]+$/.test(secretValue)) continue;

                const startCol = line.indexOf(secretValue);
                const range = new vscode.Range(i, startCol, i, startCol + secretValue.length);
                const diag = new vscode.Diagnostic(range, 'Potential hardcoded secret in package.json', vscode.DiagnosticSeverity.Warning);
                diag.code = 'coginivise.package_secret';
                diagnostics.push(diag);
            }
        }
    });

    return diagnostics;
}

// Check for vulnerable/outdated dependencies (From coginivise)
function checkDependencyVulnerabilities(pkg: string, version: string, range: vscode.Range): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];

    const vulnerablePackages: { [key: string]: { minVersion: string, maxVersion: string, cve: string, description: string } } = {
        'lodash': { minVersion: '4.17.0', maxVersion: '4.17.20', cve: 'CVE-2021-23337', description: 'Command injection vulnerability' },
        'axios': { minVersion: '0.0.0', maxVersion: '0.21.4', cve: 'CVE-2021-3749', description: 'Server-Side Request Forgery' },
        'moment': { minVersion: '0.0.0', maxVersion: '2.29.4', cve: 'CVE-2022-24785', description: 'Regular Expression Denial of Service' },
        'express': { minVersion: '0.0.0', maxVersion: '4.17.3', cve: 'CVE-2022-24999', description: 'Prototype pollution vulnerability' },
        'jquery': { minVersion: '0.0.0', maxVersion: '3.6.0', cve: 'CVE-2021-20083', description: 'Cross-site scripting vulnerability' },
        'react': { minVersion: '0.0.0', maxVersion: '17.0.2', cve: 'CVE-2022-0286', description: 'Cross-site scripting vulnerability' },
        'vue': { minVersion: '0.0.0', maxVersion: '2.6.14', cve: 'CVE-2021-32694', description: 'Cross-site scripting vulnerability' },
        'angular': { minVersion: '0.0.0', maxVersion: '13.3.0', cve: 'CVE-2022-25844', description: 'Cross-site scripting vulnerability' }
    };

    if (isOutdatedVersion(version)) {
        const diag = new vscode.Diagnostic(range, `Dependency "${pkg}" version "${version}" may be outdated`, vscode.DiagnosticSeverity.Warning);
        diag.code = 'coginivise.outdated_dependency';
        diagnostics.push(diag);
    }

    if (vulnerablePackages[pkg]) {
        const vuln = vulnerablePackages[pkg];
        if (isVersionVulnerable(version, vuln.minVersion, vuln.maxVersion)) {
            const diag = new vscode.Diagnostic(range,
                `Dependency "${pkg}" version "${version}" has known vulnerability: ${vuln.description} (${vuln.cve})`,
                vscode.DiagnosticSeverity.Error);
            diag.code = 'coginivise.vulnerable_dependency';
            diagnostics.push(diag);
        }
    }

    if (pkg.startsWith('@types/') || pkg.includes('typescript') || pkg.includes('eslint') || pkg.includes('prettier')) {
        const diag = new vscode.Diagnostic(range,
            `Development dependency "${pkg}" should not be in production dependencies`,
            vscode.DiagnosticSeverity.Warning);
        diag.code = 'coginivise.dev_dependency_in_prod';
        diagnostics.push(diag);
    }

    return diagnostics;
}

// Simple version comparison (basic implementation) (From coginivise)
function isOutdatedVersion(version: string): boolean {
    const cleanVersion = version.replace(/^[\^~]/, '');
    if (cleanVersion.startsWith('0.0.0') || cleanVersion.startsWith('0.1.') || cleanVersion.startsWith('0.2.')) {
        return true;
    }
    if (cleanVersion.startsWith('0.') && !cleanVersion.startsWith('0.0.')) {
        return true;
    }
    return false;
}

// Check if version is within vulnerable range (From coginivise)
function isVersionVulnerable(version: string, minVuln: string, maxVuln: string): boolean {
    const cleanVersion = version.replace(/^[\^~]/, '');
    const versionParts = cleanVersion.split('.').map(Number);
    const minParts = minVuln.split('.').map(Number);
    const maxParts = maxVuln.split('.').map(Number);

    for (let i = 0; i < Math.max(versionParts.length, minParts.length, maxParts.length); i++) {
        const v = versionParts[i] || 0;
        const min = minParts[i] || 0;
        const max = maxParts[i] || 0;

        if (v < min) return false;
        if (v > max) return false;
        if (v > min && v < max) return true;
    }

    return false;
}

/* ------------------- QuickFix Provider (Merge of both) ------------------- */
// Use the 'SecurityCodeActionProvider' name and merge quickfix logic
class SecurityCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        _range: vscode.Range,
        context: vscode.CodeActionContext
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];
        const secretRegexQuoted = new RegExp(
            '(api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|cred)\\s*[:=]\\s*([\'"`])([^\'"`]+)\\2',
            'i'
        );

        for (const diag of context.diagnostics) {
            // Hardcoded Secret QuickFix (Using SafePrompt's more precise replacement logic)
            if (diag.code === 'coginivise.hardcoded_secret') {
                const title = 'Replace literal with process.env reference';
                const fix = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
                fix.diagnostics = [diag];

                const lineNum = diag.range.start.line;
                const line = document.lineAt(lineNum).text;

                const secretKeyMatch = line.match(/(api[_-]?key|apikey|secret|token|password|passwd|pwd|credential|cred)/i);
                let envName = 'SECRET';
                if (secretKeyMatch && secretKeyMatch[1]) {
                    envName = secretKeyMatch[1].toUpperCase().replace(/[^A-Z0-9_]/g, '_');
                }

                const m = secretRegexQuoted.exec(line);
                const edit = new vscode.WorkspaceEdit();

                if (m && typeof m.index === 'number') {
                    const matchStart = m.index;
                    const quoteChar = m[2];
                    const openQuoteIdx = line.indexOf(quoteChar, matchStart);
                    const closeQuoteIdx = openQuoteIdx >= 0 ? line.indexOf(quoteChar, openQuoteIdx + 1) : -1;

                    if (openQuoteIdx >= 0 && closeQuoteIdx >= 0) {
                        const fixRange = new vscode.Range(lineNum, openQuoteIdx, lineNum, closeQuoteIdx + 1);
                        edit.replace(document.uri, fixRange, `process.env.${envName}`);
                    } else {
                        // Fallback logic
                        const value = m[3];
                        const valuePos = line.indexOf(value, matchStart);
                        if (valuePos >= 0) {
                            const fixRange = new vscode.Range(lineNum, valuePos, lineNum, valuePos + value.length);
                            edit.replace(document.uri, fixRange, `process.env.${envName}`);
                        } else {
                            edit.replace(document.uri, diag.range, `process.env.${envName}`);
                        }
                    }
                } else {
                    edit.replace(document.uri, diag.range, `process.env.${envName}`);
                }

                fix.edit = edit;
                fix.command = { command: 'coginivise.runScan', title: 'Rescan (coginivise)' };
                actions.push(fix);
            }

            // Missing Authorization QuickFix (From coginivise)
            else if (diag.code === 'coginivise.missing_authorization') {
                const fix = new vscode.CodeAction('Add basic authorization check stub', vscode.CodeActionKind.QuickFix);
                fix.diagnostics = [diag];

                const edit = new vscode.WorkspaceEdit();
                const insertPosition = new vscode.Position(diag.range.end.line + 1, 0); // Insert after the function declaration line
                const authCheck = `\n    // TODO: Implement proper authorization using req.user or session data\n    if (!req.user || !req.user.isAuthenticated || req.user.role !== 'admin') {\n        return res.status(403).json({ error: 'Forbidden' });\n    }\n`;

                edit.insert(document.uri, insertPosition, authCheck);
                fix.edit = edit;
                fix.command = { command: 'coginivise.runScan', title: 'Rescan (coginivise)' };
                actions.push(fix);
            }

            // Vulnerable/Outdated Dependency QuickFixes (From coginivise)
            else if (diag.code === 'coginivise.outdated_dependency' || diag.code === 'coginivise.vulnerable_dependency') {
                const fix = new vscode.CodeAction('Update to secure version (Suggest ^latest)', vscode.CodeActionKind.QuickFix);
                fix.diagnostics = [diag];
                const line = document.lineAt(diag.range.start.line).text;
                const packageMatch = line.match(/"([^"]+)":\s*"([^"]+)"/);

                if (packageMatch) {
                    const pkgName = packageMatch[1];
                    const edit = new vscode.WorkspaceEdit();
                    // Replace the existing version string with a new one
                    const startCol = line.lastIndexOf(packageMatch[2]) - 1; // Include opening quote
                    const endCol = startCol + packageMatch[2].length + 2; // Include both quotes

                    const fixRange = new vscode.Range(diag.range.start.line, startCol, diag.range.start.line, endCol);
                    edit.replace(document.uri, fixRange, `"^latest"`);

                    fix.edit = edit;
                    fix.command = { command: 'coginivise.runScan', title: 'Rescan (coginivise)' };
                    actions.push(fix);
                }
            }

            // Dev Dependency in Prod QuickFix (From coginivise)
            else if (diag.code === 'coginivise.dev_dependency_in_prod') {
                const fix = new vscode.CodeAction('Move to devDependencies', vscode.CodeActionKind.QuickFix);
                fix.diagnostics = [diag];
                const line = document.lineAt(diag.range.start.line).text;
                const packageMatch = line.match(/"([^"]+)":\s*"([^"]+)"/);

                if (packageMatch) {
                    const pkgName = packageMatch[1];
                    const pkgVersion = packageMatch[2];
                    const edit = new vscode.WorkspaceEdit();

                    // 1. Delete from dependencies
                    edit.delete(document.uri, diag.range);

                    // 2. Add to devDependencies (finding section is complex, using simple insert)
                    const content = document.getText();
                    const devDepMatch = content.match(/"devDependencies"\s*:\s*{/);
                    if (devDepMatch) {
                        const insertPos = document.positionAt(devDepMatch.index! + devDepMatch[0].length);
                        // Simple insertion might need manual formatting, but is better than nothing
                        edit.insert(document.uri, insertPos, `\n        "${pkgName}": "${pkgVersion}",`);
                    }

                    fix.edit = edit;
                    fix.command = { command: 'coginivise.runScan', title: 'Rescan (coginivise)' };
                    actions.push(fix);
                }
            }

            // SSRF Vulnerability QuickFix (From coginivise)
            else if (diag.code === 'coginivise.ssrf_vulnerability') {
                const fix = new vscode.CodeAction('Add URL validation stub to prevent SSRF', vscode.CodeActionKind.QuickFix);
                fix.diagnostics = [diag];

                const edit = new vscode.WorkspaceEdit();
                const insertPosition = new vscode.Position(diag.range.start.line, 0); // Insert before the dangerous line
                const urlValidation = `    // TODO: Implement proper URL validation to restrict external access (allowlist)\n    // if (!isInternalOrAllowedDomain(url)) { return res.status(400).end(); }\n    `;

                edit.insert(document.uri, insertPosition, urlValidation);
                fix.edit = edit;
                fix.command = { command: 'coginivise.runScan', title: 'Rescan (coginivise)' };
                actions.push(fix);
            }
        }
        return actions;
    }
}