
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Configuration from CLI args or defaults
const SRC_FILE = process.argv[2] ? path.resolve(process.argv[2]) : path.join(__dirname, 'src/components/PPsub.tsx');
let OUTPUT_FILE = process.argv[3] ? path.resolve(process.argv[3]) : path.join(__dirname, 'static/ppsub_single.html');

console.log(`Source File: ${SRC_FILE}`);
console.log(`Output File: ${OUTPUT_FILE}`);

const BUILD_DIR = path.join(__dirname, '.ppsub_build');
const TEMP_SRC = path.join(BUILD_DIR, 'PPsubModified.tsx');

// Ensure build directory exists
if (fs.existsSync(BUILD_DIR)) {
    fs.rmSync(BUILD_DIR, { recursive: true, force: true });
}
fs.mkdirSync(BUILD_DIR);

console.log('Reading source file...');
let ppSubContent = fs.readFileSync(SRC_FILE, 'utf-8');

// --- Modifications ---

// 1. Handle Logo (Inline as Data URI)
console.log('Inlining Logo...');
const logoPath = 'static/paopaogateway.svg';
let logoDataUri = '';
if (fs.existsSync(logoPath)) {
    const logoContent = fs.readFileSync(logoPath);
    const base64Logo = logoContent.toString('base64');
    logoDataUri = `data:image/svg+xml;base64,${base64Logo}`;
    // Replace the src attribute with the data URI
    ppSubContent = ppSubContent.replace('src="./paopaogateway.svg"', `src="${logoDataUri}"`);
} else {
    console.warn('Logo file not found, skipping inline.');
}
// ppSubContent = ppSubContent.replace(/<img src="\.\/paopaogateway\.svg".*?\/>/g, ''); // Don't remove it anymore

// 2. Remove "Current Config" button and handleLoadCurrentConfig
console.log('Removing Current Config button and handler...');
// Remove the button
ppSubContent = ppSubContent.replace(/<button onClick={handleLoadCurrentConfig}.*?>\s*{texts\.loadCurrent}\s*<\/button>/s, '');
// Remove the function definition (heuristic: simple regex, might need adjustment if function is complex)
// We'll replace the function body with empty or just comment it out to be safe, or remove it entirely if possible.
// Finding the function block is tricky with regex. Let's just remove the button for now.
// The unused function ref `handleLoadCurrentConfig` might cause linter errors if we were linting, but we are just building.
// However, to be clean, let's try to remove it.
// Actually, let's just leave the function definition. It won't be called.

// 3. Inject State and Header Logic
console.log('Injecting State and Header Logic...');

// Find the start of the component
const componentStartRegex = /function PPsub\(\) \{/;
const injectionPoint = ppSubContent.match(componentStartRegex);

if (injectionPoint) {
    const injectionCode = `
    // --- Injected State for Standalone Mode ---
    const [theme, setTheme] = useState(localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
    
    useEffect(() => {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        // Force background update
        document.body.style.background = theme === 'dark' ? '#202020' : '#eeeeee';
        document.body.style.color = theme === 'dark' ? '#ffffff' : '#000000';
    }, [theme]);

    const toggleTheme = () => {
        setTheme(prev => prev === 'dark' ? 'light' : 'dark');
    };

    const toggleLang = () => {
        const newLang = i18n.language.startsWith('zh') ? 'en' : 'zh';
        i18n.changeLanguage(newLang);
    };
    // ------------------------------------------
    `;
    ppSubContent = ppSubContent.replace(componentStartRegex, `function PPsub() {${injectionCode}`);
} else {
    console.error('Could not find PPsub component definition!');
    process.exit(1);
}

// 4. Inject Buttons in Header
console.log('Injecting Buttons in Header...');
// Find where the buttons are. We removed one button.
// Look for `handleExportJSON` button to place ours before/after.
const exportBtnRegex = /<button onClick={handleExportJSON}.*?>/;
const buttonsCode = `
                        {/* Injected Toggles */}
                        <button onClick={toggleTheme} style={{ ...styles.loadBtn, marginRight: '10px' }}>
                            {theme === 'dark' ? '☀️' : '🌙'}
                        </button>
                         <button onClick={toggleLang} style={{ ...styles.exportBtn, marginRight: '10px' }}>
                            {i18n.language.startsWith('zh') ? 'English' : '中文'}
                        </button>
`;
ppSubContent = ppSubContent.replace(exportBtnRegex, `${buttonsCode}$&`);


// Write Modified Component
fs.writeFileSync(path.join(BUILD_DIR, 'PPsubModified.tsx'), ppSubContent);


// --- Create Entry File ---
console.log('Creating entry.tsx...');
const entryContent = `
import React from 'react';
import ReactDOM from 'react-dom/client';
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { I18nextProvider } from 'react-i18next';
import PPsub from './PPsubModified';

// Import Locales
import { data as en } from '../src/i18n/en';
import { data as zh } from '../src/i18n/zh';

// Init i18n
i18n
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      zh: { translation: zh }
    },
    lng: navigator.language.startsWith('zh') ? 'zh' : 'en',
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false
    }
  });

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <I18nextProvider i18n={i18n}>
      <PPsub />
    </I18nextProvider>
  </React.StrictMode>
);
`;
fs.writeFileSync(path.join(BUILD_DIR, 'entry.tsx'), entryContent);

// --- Create Index HTML ---
console.log('Creating index.html...');
const htmlContent = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>PPsub Config Editor</title>
    ${logoDataUri ? `<link rel="icon" type="image/svg+xml" href="${logoDataUri}" />` : ''}
    <style>
      body { margin: 0; padding: 20px; font-family: sans-serif; transition: background 0.3s, color 0.3s; background: var(--color-background); color: var(--color-text); }
      /* Basic resets to ensure component looks okay */
      * { box-sizing: border-box; }

      /* --- CSS Variables Injection --- */
      :root {
        --color-background: #eeeeee;
        --color-background2: #ffffff;
        --color-bg-card: #ffffff;
        --color-bg-sidebar: #f8f9fa;
        --color-text: #333333;
        --color-text-secondary: #666666;
        --color-separator: #dddddd;
        --color-input-bg: #ffffff;
        --color-input-border: #cccccc;
        --btn-bg: #007bff;
        --bg-near-transparent: rgba(0,0,0,0.02);
        --color-row-odd: #f2f2f2;
        --font-normal: sans-serif;
      }

      [data-theme='dark'] {
        --color-background: #202020;
        --color-background2: #2d2d2d;
        --color-bg-card: #2d2d2d;
        --color-bg-sidebar: #252525;
        --color-text: #e0e0e0;
        --color-text-secondary: #aaaaaa;
        --color-separator: #444444;
        --color-input-bg: #333333;
        --color-input-border: #555555;
        --btn-bg: #4dabf7;
        --bg-near-transparent: rgba(255,255,255,0.05);
        --color-row-odd: #383838;
      }
      
      /* Additional Global Fixes */
      input, select, textarea {
          border: 1px solid var(--color-input-border) !important;
      }
      /* Fix Import Config Button visibility in Light Mode if it was white on white */
      /* It used var(--btn-bg) which is blueish, so it should be fine, but ensuring contrast */
    </style>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="./entry.tsx"></script>
  </body>
</html>
`;
fs.writeFileSync(path.join(BUILD_DIR, 'index.html'), htmlContent);

// --- Create Vite Config ---
console.log('Creating vite.config.ts...');
const viteConfigCheck = `
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig({
  plugins: [react()],
  root: '${BUILD_DIR}',
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsInlineLimit: 100000000, // Try to inline everything
    rollupOptions: {
      input: resolve(__dirname, '${BUILD_DIR}/index.html'),
    },
  },
  resolve: {
    alias: {
      'src': resolve(__dirname, 'src') 
    }
  }
});
`;
// Adjust alias to point back to real src
// The build dir is .ppsub_build in root.
// So __dirname is root.
// 'src' alias should point to root/src.

const viteConfigContent = `
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  root: path.resolve(__dirname, '${BUILD_DIR}'),
  base: './', // Relative base
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsInlineLimit: 100000000, // Try to inline everything
  },
  resolve: {
    alias: {
      'src': path.resolve(__dirname, 'src'),
      'react': path.resolve(__dirname, 'node_modules/react'),
      'react-dom': path.resolve(__dirname, 'node_modules/react-dom'),
      'react/jsx-runtime': path.resolve(__dirname, 'node_modules/react/jsx-runtime.js'),
      'i18next': path.resolve(__dirname, 'node_modules/i18next'),
      'react-i18next': path.resolve(__dirname, 'node_modules/react-i18next'),
    }
  }
});
`;
fs.writeFileSync('vite.config.ppsub.ts', viteConfigContent);

// --- Run Build ---
console.log('Running Vite Build...');
try {
    const nodePath = process.execPath;
    const vitePath = path.join('node_modules', 'vite', 'bin', 'vite.js');
    execSync(`"${nodePath}" "${vitePath}" build --config vite.config.ppsub.ts`, { stdio: 'inherit' });
} catch (e) {
    console.error('Build failed.');
    process.exit(1);
}

// --- Inline Assets ---
console.log('Inlining Assets...');
const distDir = path.join(BUILD_DIR, 'dist');
const indexHtmlPath = path.join(distDir, 'index.html');
let indexHtml = fs.readFileSync(indexHtmlPath, 'utf-8');

// Find JS and CSS files
const assetsDir = path.join(distDir, 'assets');
const files = fs.readdirSync(assetsDir);

files.forEach(file => {
    const filePath = path.join(assetsDir, file);
    if (file.endsWith('.js')) {
        const jsContent = fs.readFileSync(filePath, 'utf-8');
        indexHtml = indexHtml.replace(/<script type="module".*?src=".*?"><\/script>/, () => `<script type="module">${jsContent}</script>`);
        // Also remove any preload links for this script
        // <link rel="modulepreload" ... href="...">
        // Simple regex to catch standard vite output
        const preloadRegex = new RegExp(`<link rel="modulepreload".*?href=".*?${file}">`);
        indexHtml = indexHtml.replace(preloadRegex, '');
    } else if (file.endsWith('.css')) {
        const cssContent = fs.readFileSync(filePath, 'utf-8');
        indexHtml = indexHtml.replace(/<link rel="stylesheet".*?href=".*?">/, `<style>${cssContent}</style>`);
    }
});

// Final Cleanup of untouched tags if any (robustness)
// (Skip for now, assuming standard Vite output)

// --- Write Output ---
console.log(`Writing output to ${OUTPUT_FILE}...`);
if (!fs.existsSync(path.dirname(OUTPUT_FILE))) {
    fs.mkdirSync(path.dirname(OUTPUT_FILE));
}
fs.writeFileSync(OUTPUT_FILE, indexHtml);

// --- Cleanup ---
console.log('Cleaning up...');
fs.rmSync(BUILD_DIR, { recursive: true, force: true });
fs.rmSync('vite.config.ppsub.ts');

console.log('Done!');
