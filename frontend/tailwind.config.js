/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#faf8f5',
          panel: '#ffffff',
          border: '#e7e2d8',
          crimson: '#dc2626',
          red: '#b91c1c',
          amber: '#d97706',
          emerald: '#059669',
          stone: '#1c1917'
        }
      }
    },
  },
  plugins: [],
}
