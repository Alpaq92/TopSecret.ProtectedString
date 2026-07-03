// Boots the .NET WebAssembly runtime and bridges Console.Out to xterm.js.
// xterm.js itself is loaded (version-pinned) from index.html.
import { dotnet } from './_framework/dotnet.js';

// --- Theme handling: light / dark / system (default system, persisted) ---
const TERM_THEMES = {
    dark: {
        background: '#101014',
        foreground: '#d4d4d8',
        cursor: '#d4d4d8',
        selectionBackground: '#3a3a46',
    },
    light: {
        background: '#f5f5f7',
        foreground: '#1b1b1f',
        cursor: '#1b1b1f',
        selectionBackground: '#c9d6e8',
    },
};

const systemDark = window.matchMedia('(prefers-color-scheme: dark)');
const themeSelect = document.getElementById('theme');

function resolvedTheme(mode) {
    return mode === 'system' ? (systemDark.matches ? 'dark' : 'light') : mode;
}

function applyTheme(mode) {
    const resolved = resolvedTheme(mode);
    document.documentElement.dataset.theme = resolved;
    if (term) term.options.theme = TERM_THEMES[resolved];
}

let themeMode = localStorage.getItem('topsecret-demo-theme') ?? 'system';
if (!['system', 'light', 'dark'].includes(themeMode)) themeMode = 'system';
themeSelect.value = themeMode;

themeSelect.addEventListener('change', () => {
    themeMode = themeSelect.value;
    localStorage.setItem('topsecret-demo-theme', themeMode);
    applyTheme(themeMode);
});
systemDark.addEventListener('change', () => {
    if (themeMode === 'system') applyTheme(themeMode);
});

// Apply the page theme before the terminal exists so there is no flash.
let term = null;
applyTheme(themeMode);

// --- Terminal ---
term = new Terminal({
    convertEol: true, // xterm translates \n -> \r\n; keeps the C# writer trivial
    cursorBlink: false,
    disableStdin: true, // the demo is write-only
    fontFamily: '"Cascadia Mono", "Consolas", monospace',
    fontSize: 14,
    theme: TERM_THEMES[resolvedTheme(themeMode)],
});
// Fit addon sizes the terminal grid to fill its container (which flexes to
// the viewport height) and re-fits on window resize.
const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open(document.getElementById('terminal'));
const refit = () => { try { fitAddon.fit(); } catch { /* pre-open */ } };
refit();
window.addEventListener('resize', refit);
term.writeln('Loading .NET WebAssembly runtime…');

// create() instantiates and starts the runtime WITHOUT running Main. We
// never call dotnet.run()/runMain() — both EXIT the runtime when Main
// returns, which would leave "Run again" calling into a dead runtime
// ("runtime already exited"). Instead the runtime stays alive and every
// pass — the initial one and each button press — is the same [JSExport]
// RunDemo() call.
const { setModuleImports, getAssemblyExports, getConfig } = await dotnet
    .withDiagnosticTracing(false)
    .create();

setModuleImports('main.js', {
    term: {
        write: (text) => term.write(text),
    },
});

const exports = await getAssemblyExports(getConfig().mainAssemblyName);
const rerun = document.getElementById('rerun');

async function runDemo() {
    rerun.disabled = true;
    term.clear();
    try {
        await exports.TopSecret.DemoWasm.Program.RunDemo();
    } finally {
        rerun.disabled = false;
    }
}

rerun.addEventListener('click', runDemo);
await runDemo(); // initial pass
