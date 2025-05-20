function getTodaysActivityEmail(data) {
  const {
    actions = [
      { type: "Resolved", cve: "CVE-2024-12345", status: "✅ Fixed" },
      { type: "Ignored", cve: "CVE-2024-67890", status: "⚠️ Low Risk" },
      { type: "Resolved", cve: "CVE-2024-11223", status: "✅ Fixed" },
      { type: "Ignored", cve: "CVE-2024-33445", status: "⚠️ Low Risk" },
      { type: "Resolved", cve: "CVE-2024-55667", status: "✅ Fixed" }
    ],
    // productVersionUpdates = [
    //   { product: "Apache Server", version: "⬆️ Upgraded to v2.4.58" },
    //   { product: "NGINX", version: "⬆️ Upgraded to v1.21.6" }
    // ],
    watchlistUpdates = [
      { product: "Google Chrome", status: "📌 Added to Watchlist" },
      { product: "Microsoft Edge", status: "📌 Added to Watchlist" }
    ]
  } = data;

  const actionRows = actions.map(action => `
    <tr>
      <td style="padding: 8px; border: 1px solid #444; font-size: 14px;">${action.type}</td>
      <td style="padding: 8px; border: 1px solid #444; font-size: 14px;">${action.cve}</td>
      <td style="padding: 8px; border: 1px solid #444; font-size: 14px;">${action.status}</td>
    </tr>
  `).join("");
  const watchlistRows = watchlistUpdates.map(update => `
    <tr>
        <td style="padding: 8px; border: 1px solid #444; font-size: 14px;">${update.product}</td>
        <td style="padding: 8px; border: 1px solid #444; font-size: 14px;">${update.status}</td>
    </tr>
  `).join("");

  return `
  <div style="background: url('https://img.freepik.com/free-vector/copy-space-blue-circuits-digital-background_23-2148821699.jpg?t=st=1742457082~exp=1742460682~hmac=f88329f39e166167aea70ffb01e4234e8087ffb4ad7058cd33c27c73989ed4bd&w=1380') no-repeat center center; background-size: cover; background-color: #001133; color: white; padding: 20px; text-align: center; font-family: Arial, sans-serif;">
    <div style="max-width: 600px; width: 95%; margin: 0 auto; background: rgba(0, 11, 43, 0.9); padding: 20px; border-radius: 10px;">
      
      <!-- Logo -->
      <div style="text-align: center; padding-bottom: 10px;">
        <img src="https://static.wixstatic.com/media/e48a18_c949f6282e6a4c8e9568f40916a0c704~mv2.png/v1/crop/x_0,y_151,w_1920,h_746/fill/w_310,h_120,fp_0.50_0.50,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/For%20Dark%20Theme.png" alt="DeepCytes Logo" width="120" style="display: block; margin: 0 auto;">
      </div>

      <!-- Heading -->
      <h1 style="color: #ffffff; font-size: 22px; font-family: 'Playfair Display', serif; margin-bottom: 10px;">Today's CVE Activity Summary</h1>
      <p style="color: #d0d0d0; font-size: 14px;">A recap of today's security updates & actions performed.</p>


      <!-- All Actions Table -->
      <div style="margin-top: 25px; background: rgba(26, 43, 77, 0.8); padding: 12px; border-radius: 10px;">
        <h2 style="font-size: 18px; font-family: 'Playfair Display', serif; text-align: center;">📌 All Actions Performed Today</h2>
        <table align="center" width="100%" style="border-collapse: collapse;">
          <tr style="background: #263D6D; color: white;">
            <th style="padding: 8px; border: 1px solid #444;">Action</th>
            <th style="padding: 8px; border: 1px solid #444;">CVE ID / Product</th>
            <th style="padding: 8px; border: 1px solid #444;">Status</th>
          </tr>
          ${actionRows}
        </table>
      </div>
      
      <!-- Watchlist Updates Table -->
      <div style="margin-top: 20px; background: rgba(26, 43, 77, 0.8); padding: 12px; border-radius: 10px;">
          <h2 style="font-size: 18px; font-family: 'Playfair Display', serif; text-align: center;">📌 Watchlist Updates</h2>
          <table align="center" width="100%" style="border-collapse: collapse; background: transparent;">
              <tr style="background: #263D6D; color: white;">
                  <th style="padding: 8px; border: 1px solid #444;">Product</th>
                  <th style="padding: 8px; border: 1px solid #444;">Status</th>
              </tr>
              ${watchlistRows}
          </table>
      </div>


      <!-- CTA Button -->
      <div style="margin-top: 30px; text-align: center;">
        <a href="#" style="background: white; color: black; padding: 12px 20px; font-size: 14px; text-decoration: none; font-weight: bold; border-radius: 6px; display: inline-block;">🔎 View Full Report</a>
      </div>
    </div>
  </div>
  `;
}

module.exports = { getTodaysActivityEmail };
