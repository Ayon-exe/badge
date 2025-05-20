function getUpdateEmail(data) {
  const result = data || {
      resolvedCves: [
          { id: "CVE-2024-12345", product: "Apache Server", status: "✅ Fixed" },
          { id: "CVE-2024-67890", product: "Linux Kernel", status: "✅ Fixed" }
      ],
      // productUpdates: [
      //     { product: "Windows Defender", version: "Updated to v5.0.2" },
      //     { product: "MySQL Database", version: "Upgraded to v8.0.35" }
      // ],
      watchlistUpdates: [
          { product: "Google Chrome", status: "📌 Added to Watchlist" }
      ]
  };

  const resolvedRows = result.resolvedCves.map(cve => `
    <tr>
      <td style="padding: 8px; border: 1px solid #444;">${cve.id}</td>
      <td style="padding: 8px; border: 1px solid #444;">${cve.product}</td>
      <td style="padding: 8px; border: 1px solid #444;">${cve.status}</td>
    </tr>
  `).join("");

  // const productUpdateRows = result.productUpdates.map(update => `
  //   <tr>
  //     <td style="padding: 8px; border: 1px solid #444;">${update.product}</td>
  //     <td style="padding: 8px; border: 1px solid #444;">${update.version}</td>
  //   </tr>
  // `).join("");

  const watchlistRows = result.watchlistUpdates.map(update => `
    <tr>
      <td style="padding: 8px; border: 1px solid #444;">${update.product}</td>
      <td style="padding: 8px; border: 1px solid #444;">${update.status}</td>
    </tr>
  `).join("");

  return `
  <div style="background: url('https://img.freepik.com/free-vector/copy-space-blue-circuits-digital-background_23-2148821699.jpg?t=st=1742457082~exp=1742460682~hmac=f88329f39e166167aea70ffb01e4234e8087ffb4ad7058cd33c27c73989ed4bd&w=1380') no-repeat center center; background-size: cover; background-color: #001133; color: white; padding: 20px; text-align: center; font-family: Arial, sans-serif;">
    <div style="max-width: 550px; width: 90%; margin: 0 auto; background: rgba(0, 11, 43, 0.9); padding: 20px; border-radius: 10px;">
      
      <!-- Logo -->
      <div style="text-align: center; padding-bottom: 15px;">
        <img src="https://static.wixstatic.com/media/e48a18_c949f6282e6a4c8e9568f40916a0c704~mv2.png/v1/crop/x_0,y_151,w_1920,h_746/fill/w_310,h_120,fp_0.50_0.50,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/For%20Dark%20Theme.png" alt="DeepCytes Logo" width="120" style="display: block; margin: 0 auto;">
      </div>

      <h1 style="color: #ffffff; font-size: 22px; font-family: 'Playfair Display', serif;">Your CVE Updates</h1>
      <p style="color: #d0d0d0;">Here’s a summary of the latest security actions performed.</p>

      <!-- Metrics Section (Fixed for Mobile) -->
      <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 20px; margin-top: 20px;">
        <div style="background: rgba(26, 43, 77, 0.8); padding: 15px; border-radius: 8px; text-align: center; width: 100%; max-width: 220px;">
          <h2 style="color: #ffffff; font-size: 18px; margin-bottom: 5px;">✅ ${result.resolvedCves.length}</h2>
          <p style="color: #d0d0d0; font-size: 13px;">CVEs Resolved</p>
        </div>
       <!--  
             <div style="background: rgba(26, 43, 77, 0.8); padding: 15px; border-radius: 8px; text-align: center; width: 100%; max-width: 220px;">
               <h2 style="color: #ffffff; font-size: 18px; margin-bottom: 5px;">🔄 ${result.productUpdates.length}</h2>
               <p style="color: #d0d0d0; font-size: 13px;">Product Updates</p>
             </div>
         -->
      </div>

      <!-- CVEs Resolved Table -->
      <div style="margin-top: 25px; background: rgba(26, 43, 77, 0.8); padding: 12px; border-radius: 10px;">
        <h2 style="font-size: 18px; text-align: center;">✅ Resolved CVEs</h2>
        <table align="center" width="100%" style="border-collapse: collapse;">
          <tr style="background: #263D6D; color: white;">
            <th style="padding: 8px; border: 1px solid #444;">CVE ID</th>
            <th style="padding: 8px; border: 1px solid #444;">Product</th>
            <th style="padding: 8px; border: 1px solid #444;">Status</th>
          </tr>
          ${resolvedRows}
        </table>
      </div>

      <!-- Product Updates Table -->
      <div style="margin-top: 25px; background: rgba(26, 43, 77, 0.8); padding: 12px; border-radius: 10px;">
        <h2 style="font-size: 18px; text-align: center;">🔄 Product Updates</h2>
        <table align="center" width="100%" style="border-collapse: collapse;">
          <tr style="background: #263D6D; color: white;">
            <th style="padding: 8px; border: 1px solid #444;">Product</th>
            <th style="padding: 8px; border: 1px solid #444;">Version</th>
          </tr>
          ${productUpdateRows}
        </table>
      </div>

      <!-- Watchlist Updates -->
      <div style="margin-top: 25px; background: rgba(26, 43, 77, 0.8); padding: 12px; border-radius: 10px;">
        <h2 style="font-size: 18px; text-align: center;">📌 Watchlist Updates</h2>
        <table align="center" width="100%" style="border-collapse: collapse;">
          <tr style="background: #263D6D; color: white;">
            <th style="padding: 8px; border: 1px solid #444;">Product</th>
            <th style="padding: 8px; border: 1px solid #444;">Status</th>
          </tr>
          ${watchlistRows}
        </table>
      </div>

      <!-- CTA Button -->
      <div style="margin-top: 30px; text-align: center;">
        <a href="#" style="background: white; color: black; padding: 12px 20px; font-size: 14px; text-decoration: none; font-weight: bold; border-radius: 6px; display: inline-block;">🔎 View All Updates</a>
      </div>
    </div>
  </div>
  `;
}

module.exports = { getUpdateEmail };
