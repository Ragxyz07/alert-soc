/** @type {import('tailwindcss').Config} */
export default {
  content: ['./*.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#05070a',
        'ink-2': '#0a0e12',
        bone: '#dfe7e0',
        'bone-dim': '#aab4ad',
        muted: '#78837c',
        line: 'rgba(223,231,224,.13)',
        'line-soft': 'rgba(223,231,224,.07)',
        vermilion: '#e0231c',
        ember: '#ff5a3c',
        gold: '#c9a24a',
        sage: '#7fa99b',
      },
      fontFamily: {
        sans: ['Onest', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
      letterSpacing: {
        cinematic: '.2em',
      },
      animation: {
        'fade-up': 'fade-up .7s ease-out both',
        'critical-pulse': 'critical-pulse 4.4s ease-in-out infinite',
        'ember-drift': 'ember-drift 24s linear infinite',
      },
      keyframes: {
        'fade-up': {
          from: { opacity: '0', transform: 'translateY(14px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'critical-pulse': {
          '0%, 100%': { boxShadow: '0 0 0 rgba(224,35,28,0)' },
          '50%': { boxShadow: '0 0 22px rgba(224,35,28,.14)' },
        },
        'ember-drift': {
          from: { transform: 'translateY(105vh) translateX(0)', opacity: '0' },
          '10%': { opacity: '.7' },
          '90%': { opacity: '.45' },
          to: { transform: 'translateY(-15vh) translateX(28px)', opacity: '0' },
        },
      },
    },
  },
  plugins: [],
};
