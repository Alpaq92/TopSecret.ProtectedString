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
const terminalEl = document.getElementById('terminal');
term.loadAddon(fitAddon);
term.open(terminalEl);

// Write at the default grid size first so output is never lost, THEN fit —
// only when the container actually has a size (a zero-size fit would set
// 0 rows and swallow every subsequent write). Fit on the next frame (after
// layout) and on resize.
term.writeln('Loading .NET WebAssembly runtime…');
const refit = () => {
    if (terminalEl.clientHeight > 0 && terminalEl.clientWidth > 0) {
        try { fitAddon.fit(); } catch { /* ignore transient sizing errors */ }
    }
};
requestAnimationFrame(refit);
window.addEventListener('resize', refit);

// create() instantiates and starts the runtime WITHOUT running Main. We
// never call dotnet.run()/runMain() — both EXIT the runtime when Main
// returns, which would leave "Run again" calling into a dead runtime
// ("runtime already exited"). Instead the runtime stays alive and every
// pass — the initial one and each button press — is the same [JSExport]
// RunDemo() call.
const { setModuleImports, getAssemblyExports, getConfig } = await dotnet
    .withDiagnosticTracing(false)
    .create();

// The WASM demo produces all its output synchronously, then returns; if we
// wrote each line straight to xterm the whole run would paint in one frame.
// Instead C# enqueues completed lines here and a render loop drains them one
// line per ~14 ms, giving a live, line-by-line feel.
const lineQueue = [];
setModuleImports('main.js', {
    term: {
        enqueue: (line) => lineQueue.push(line),
    },
});
setInterval(() => {
    if (lineQueue.length) term.writeln(lineQueue.shift());
}, 14);

const exports = await getAssemblyExports(getConfig().mainAssemblyName);
const rerun = document.getElementById('rerun');

async function runDemo(isRerun) {
    rerun.disabled = true;
    if (isRerun) {
        // Clear and immediately show a status line (mirroring the initial
        // run's "Loading…") so the terminal is never blank while the runtime
        // re-runs and the first output lines start streaming in.
        term.clear();
        lineQueue.length = 0;
        term.writeln('Re-running the demo on the .NET WebAssembly runtime…');
    }
    try {
        await exports.TopSecret.DemoWasm.Program.RunDemo();
    } finally {
        rerun.disabled = false;
    }
}

rerun.addEventListener('click', () => runDemo(true)); // clear + immediate status, then stream
await runDemo(false); // initial pass keeps the "Loading…" line, then streams
