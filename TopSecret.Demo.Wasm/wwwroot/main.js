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
term.open(document.getElementById('terminal'));
term.writeln('Loading .NET WebAssembly runtime…');

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
rerun.addEventListener('click', async () => {
    rerun.disabled = true;
    term.clear();
    try {
        await exports.TopSecret.DemoWasm.Program.RunDemo();
    } finally {
        rerun.disabled = false;
    }
});

// dotnet.run() executes Main (the first demo pass) and resolves when it
// returns; the runtime stays alive for the button's re-runs. finally: the
// retry button must come alive even (especially) when the first pass fails.
try {
    await dotnet.run();
} finally {
    rerun.disabled = false;
}
