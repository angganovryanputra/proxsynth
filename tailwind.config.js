/** Tailwind build config — precompiled to a static stylesheet so the browser
 *  no longer runs the JIT compiler at load time (removes FOUC + runtime lag).
 *  Build: npx tailwindcss@3 -c tailwind.config.js -i frontend/src/tw-input.css \
 *         -o frontend/css/tailwind.build.css --minify
 */
module.exports = {
  darkMode: 'class',
  content: ['./frontend/**/*.html', './frontend/**/*.js'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
};
