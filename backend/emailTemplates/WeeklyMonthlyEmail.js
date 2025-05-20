function getWeeklyMonthlyEmail(data) {
  const mailData = data || {
      resolvedCves: 15,
      newCves: 7,
      nonFixedCves: 5,
      comparisons: {
          lastWeek: "12 CVEs Resolved",
          thisWeek: "15 CVEs Resolved"
      },
      notableFixes: [
          { product: "Apache Server", issue: "Fixed Remote Code Execution Vulnerability" },
          { product: "Google Chrome", issue: "Patched Zero-Day Exploit" }
      ]
  };

  // const notableFixesRows = mailData.notableFixes.map(fix => `
  //   <tr>
  //     <td style="padding: 8px; border: 1px solid #444;">${fix.product}</td>
  //     <td style="padding: 8px; border: 1px solid #444;">${fix.issue}</td>
  //   </tr>
  // `).join("");

  return `
  <div style="background: url('https://img.freepik.com/free-vector/copy-space-blue-circuits-digital-background_23-2148821699.jpg?t=st=1742457082~exp=1742460682~hmac=f88329f39e166167aea70ffb01e4234e8087ffb4ad7058cd33c27c73989ed4bd&w=1380') no-repeat center center; background-size: cover; background-color: #001133; color: white; padding: 20px; text-align: center; font-family: Arial, sans-serif;">
    <div style="max-width: 550px; width: 90%; margin: 0 auto; background: rgba(0, 11, 43, 0.9); padding: 20px; border-radius: 10px; text-align: center;">
      
      <!-- Logo -->
      <div style="text-align: center; padding-bottom: 15px;">
        <img src="https://static.wixstatic.com/media/e48a18_c949f6282e6a4c8e9568f40916a0c704~mv2.png/v1/crop/x_0,y_151,w_1920,h_746/fill/w_310,h_120,fp_0.50_0.50,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/For%20Dark%20Theme.png" alt="DeepCytes Logo" width="120" style="display: block; margin: 0 auto;">
      </div>

      <!-- Heading -->
      <h1 style="color: #ffffff; font-size: 20px; font-family: 'Playfair Display', serif; margin-bottom: 10px;">📆 Weekly Security Report</h1>
      <p style="color: #d0d0d0; font-size: 14px;">A summary of security trends from the past week/month.</p>

      <!-- Metrics Section (Fixed for Mobile) -->
      <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 20px; margin-top: 20px;">
        <div style="background: rgba(26, 43, 77, 0.8); padding: 15px; border-radius: 8px; text-align: center; width: 100%; max-width: 220px;">
          <h2 style="color: #ffffff; font-size: 18px; margin-bottom: 5px;">✅ ${mailData.resolvedCves}</h2>
          <p style="color: #d0d0d0; font-size: 13px;">CVEs Resolved</p>
        </div>
        <div style="background: rgba(26, 43, 77, 0.8); padding: 15px; border-radius: 8px; text-align: center; width: 100%; max-width: 220px;">
          <h2 style="color: #ffffff; font-size: 18px; margin-bottom: 5px;">⚠️ ${mailData.newCves}</h2>
          <p style="color: #d0d0d0; font-size: 13px;">New CVEs Found</p>
        </div>
      </div>

      <!-- Non-Fixed CVEs -->
      <div style="background: rgba(26, 43, 77, 0.8); margin-top: 25px; padding: 15px; border-radius: 10px;">
        <h2 style="color: #ffffff; font-size: 18px;">🚧 Pending Fixes</h2>
        <p style="color: #d0d0d0; font-size: 14px;">${mailData.nonFixedCves} vulnerabilities have patches available but remain unpatched.</p>
      </div>

      <!-- Comparison Section -->
      <div style="background: rgba(26, 43, 77, 0.8); margin-top: 25px; padding: 15px; border-radius: 10px;">
        <h2 style="color: #ffffff; font-size: 18px;">📊 Trend Comparison</h2>
        <p style="color: #d0d0d0; font-size: 14px;">Last Week: <strong>${mailData.comparisons.lastWeek}</strong></p>
        <p style="color: #d0d0d0; font-size: 14px;">This Week: <strong>${mailData.comparisons.thisWeek}</strong></p>
      </div>

      <!-- Notable Fixes -->
      <!-- 
      <div style="background: rgba(26, 43, 77, 0.8); margin-top: 25px; padding: 15px; border-radius: 10px;">
        <h2 style="color: #ffffff; font-size: 18px;">🔍 Notable Fixes</h2>
        <table align="center" width="100%" style="border-collapse: collapse;">
          <tr style="background: #263D6D; color: white;">
            <th style="padding: 8px; border: 1px solid #444;">Product</th>
            <th style="padding: 8px; border: 1px solid #444;">Fix Details</th>
          </tr>
          <!-- $ {notableFixesRows} -->
        </table>
      </div>
     -->

      <!-- CTA Button -->
      <div style="margin-top: 30px; text-align: center;">
        <a href="#" style="background: white; color: black; padding: 12px 20px; font-size: 14px; text-decoration: none; font-weight: bold; border-radius: 6px; display: inline-block;">🔎 View Full Report</a>
      </div>
    </div>
  </div>
  `;
}

module.exports = { getWeeklyMonthlyEmail };
