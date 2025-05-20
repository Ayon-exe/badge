function getWelcomeEmail(userName = "there") {
    return `
    <div style="background: url('https://img.freepik.com/free-vector/copy-space-blue-circuits-digital-background_23-2148821699.jpg?t=st=1742457082~exp=1742460682~hmac=f88329f39e166167aea70ffb01e4234e8087ffb4ad7058cd33c27c73989ed4bd&w=1380') no-repeat center center; background-size: cover; background-color: #001133; color: white; padding: 20px; text-align: center; font-family: Arial, sans-serif;">
      <div style="max-width: 600px; width: 95%; margin: 0 auto; background: rgba(0, 11, 43, 0.9); padding: 20px; border-radius: 10px;">
        
        <!-- Logo -->
        <div style="text-align: center; padding-bottom: 10px;">
          <img src="https://static.wixstatic.com/media/e48a18_c949f6282e6a4c8e9568f40916a0c704~mv2.png/v1/crop/x_0,y_151,w_1920,h_746/fill/w_310,h_120,fp_0.50_0.50,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/For%20Dark%20Theme.png" alt="DeepCytes Logo" width="120" style="display: block; margin: 0 auto;">
        </div>
  
        <!-- Heading -->
        <h1 style="color: #ffffff; font-size: 24px; font-family: 'Playfair Display', serif; margin-bottom: 10px;">👋 Welcome, ${userName}!</h1>
        <p style="color: #d0d0d0; font-size: 15px;">We’re excited to have you on board with DeepCytes.</p>
  
        <!-- Welcome Info Block -->
        <div style="margin-top: 25px; background: rgba(26, 43, 77, 0.8); padding: 18px; border-radius: 10px;">
          <h2 style="font-size: 18px; font-family: 'Playfair Display', serif; text-align: center;">🔐 Your Dashboard Awaits</h2>
          <p style="font-size: 14px; line-height: 1.6; margin-top: 10px;">
            Track real-time vulnerabilities, manage your product watchlists, and receive daily intelligence alerts — all in one place.
          </p>
        </div>
  
        <!-- Quick Start Tips -->
        <div style="margin-top: 20px; background: rgba(26, 43, 77, 0.8); padding: 18px; border-radius: 10px;">
          <h2 style="font-size: 18px; font-family: 'Playfair Display', serif; text-align: center;">🚀 Getting Started</h2>
          <ul style="text-align: left; padding-left: 20px; font-size: 14px; line-height: 1.8; margin-top: 10px;">
            <li>🔎 Add products to your <strong>Watchlist</strong></li>
            <li>📬 Set up email alerts for new CVEs</li>
            <li>📊 View detailed analytics & patch history</li>
            <li>🧠 Explore your threat landscape daily</li>
          </ul>
        </div>
  
        <!-- CTA Button -->
        <div style="margin-top: 30px; text-align: center;">
          <a href="https://www.deepcytes.io/" style="background: white; color: black; padding: 12px 20px; font-size: 14px; text-decoration: none; font-weight: bold; border-radius: 6px; display: inline-block;">🛡 Go to Dashboard</a>
        </div>
  
        <!-- Footer -->
        <p style="color: #aaa; font-size: 12px; margin-top: 20px;">
          Need help? Reach out to our support team any time.<br>
          DeepCytes | Cyber Threat Intelligence
        </p>
      </div>
    </div>
    `;
  }
  
  module.exports = { getWelcomeEmail };
      