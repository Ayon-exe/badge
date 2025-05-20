module.exports = {
  content: [
    '@/pages/**/*.{js,ts,jsx,tsx}',
    '@/components/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {},
  },
  plugins: [],
  extend: {
  animation: {
    float: "float 3s ease-in-out infinite",
  },
  keyframes: {
    float: {
      "0%, 100%": { transform: "translateY(0px)" },
      "50%": { transform: "translateY(-10px)" },
    },
  },
},

}
