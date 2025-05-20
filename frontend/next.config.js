module.exports = {
    images: {
      localPatterns: [
        {
          pathname: '/assets/images/**',
          search: '',
        },
      ],
    },
    reactStrictMode: true,
    env: {
      SERVER_URL: process.env.SERVER_URL,
    }
  }
