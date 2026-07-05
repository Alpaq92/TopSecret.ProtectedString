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
//
// The loading line animates in place — "." -> ".." -> "..." -> "." -> ... —
// via the CUP escape \x1b[H (cursor to row 1, col 1) + term.write (not
// writeln, which would print a new line every frame). CUP-to-home is used
// instead of a bare \r: this line is the very first thing written to the
// terminal, so if it's ever wide enough to soft-wrap onto a second row, \r
// alone would return to column 0 of whatever row the cursor ended up on
// (the wrapped second row), not the true start of the line — every
// subsequent frame would then render one row lower, corrupting the display
// instead of overwriting cleanly. Padded to a fixed 3-dot width so a
// shorter frame can't leave a stray character from a longer one uncleared.
// Runs only while the boot is the only thing on screen; stopped the
// instant dotnet.create() resolves, before any real demo output starts.
//
// The first frame paints immediately (not on the first timer tick) and the
// cadence is fast (90ms): the whole boot can finish in well under a
// second — on a warm cache, network fetches are near-instant and only the
// WASM instantiation + .NET startup remain — so a slower cadence risked
// only 3-4 visible frames total, barely readable as motion.
const CUP_HOME = '\x1b[H'; // cursor to row 1, col 1 — see rationale above
const LOADING_TEXT = 'Loading .NET WebAssembly runtime';
const LOADING_FRAMES = ['.  ', '.. ', '...']; // the only 3 states this ever renders
let loadingFrame = -1; // pre-increment below lands the first call on index 0
const paintLoadingFrame = () => {
    loadingFrame = (loadingFrame + 1) % LOADING_FRAMES.length;
    term.write(CUP_HOME + LOADING_TEXT + LOADING_FRAMES[loadingFrame]);
};
paintLoadingFrame();
const loadingAnimation = setInterval(paintLoadingFrame, 90);
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

clearInterval(loadingAnimation);
term.write(CUP_HOME + LOADING_TEXT + '...\n'); // settle on a clean final frame before real output starts

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
    if (lineQueue.length) {
        term.writeln(lineQueue.shift());
        term.scrollToBottom(); // keep the newest line in view as output streams
    }
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
        // RunDemo() below runs synchronously on the main thread once called —
        // without yielding here first, the clear + status line above would
        // never get painted before that call locks up the tab, making the
        // click look like it did nothing until the whole run finishes.
        // A setTimeout(0) yield gives the browser a chance to paint; unlike
        // requestAnimationFrame it still fires when the tab isn't visible or
        // has no active compositor, so this can't hang indefinitely.
        await new Promise((resolve) => setTimeout(resolve, 0));
    }
    try {
        await exports.TopSecret.DemoWasm.Program.RunDemo();
    } finally {
        rerun.disabled = false;
    }
}

rerun.addEventListener('click', () => runDemo(true)); // clear + immediate status, then stream
await runDemo(false); // initial pass keeps the "Loading…" line, then streams
