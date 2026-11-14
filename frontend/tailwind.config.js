/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        border: 'hsl(214.3 31.8% 91.4%)',
        background: 'hsl(210 40% 98%)',
        foreground: 'hsl(222.2 84% 4.9%)',
      },
    },
  },
  plugins: [],
};
