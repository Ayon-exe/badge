function getActionEmail(data) {
  const newCves =  data || {msg: "Vendor Microsoft has been Added to Hello"};

  return `
  <div style="background: url('/stacked-waves-haikei.png') no-repeat center center; background-size: cover; background-color: #001133; color: white; padding: 20px; text-align: center; font-family: Arial, sans-serif;">
    <div style="max-width: 600px; width: 100%; margin: 0 auto; background: rgba(0, 11, 43, 0.9); padding: 15px; border-radius: 10px;">
      
      <!-- Logo -->
      <div style="text-align: center; padding-bottom: 10px;">
        <img src="https://static.wixstatic.com/media/e48a18_c949f6282e6a4c8e9568f40916a0c704~mv2.png/v1/crop/x_0,y_151,w_1920,h_746/fill/w_310,h_120,fp_0.50_0.50,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/For%20Dark%20Theme.png" alt="DeepCytes Logo" width="100" style="display: block; margin: 0 auto;">
      </div>

      <!-- Alert Header -->
      <h1 style="color: #ffffff; font-size: 22px; font-family: 'Playfair Display', serif;">🚨 Watchlist Alert</h1>
      <p style="color: #d0d0d0;">New watchlist activity have been detected.</p>

      <!-- CVE Details Table -->
      <div style="margin-top: 20px; background: rgba(26, 43, 77, 0.8); padding: 12px; border-radius: 10px;">
        <h2 style="font-size: 18px; font-family: 'Playfair Display', serif; text-align: center;">New Activity</h2>
          ${newCves.msg}
      </div>

      <!-- Actions & Recommendations -->
      <div style="margin-top: 15px; background: rgba(26, 43, 77, 0.8); padding: 15px; border-radius: 10px;">
        <p style="text-align: center; font-size: 14px; color: #d0d0d0;">
          <i> ⚠️ If it was not you, change your password immediatly. </i> <br>
        </p>
      </div>

      <!-- CTA Button -->
      <div style="margin-top: 20px; text-align: center;">
        <a href="#" style="background: white; color: black; padding: 12px 20px; font-size: 14px; text-decoration: none; font-weight: bold; border-radius: 6px; display: inline-block;">Log in 🕸️  </a>
      </div>
    </div>
  </div>
  `;
}

module.exports = { getActionEmail };
