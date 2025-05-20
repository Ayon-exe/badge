function getAlertEmail(data) {
  const newCves = data || [
      { cve_id: "CVE-2024-12345", description: "Processing a file may lead to a denial-of-service or potentially disclose memory contents. This issue is fixed in macOS 14. The issue was addressed with improved checks.", cvss_score: 9.8, product: "iOS and iPadOS, iOS and iPadOS, macOS, macOS, macOS", published_at: "2024-03-12 10:45 AM" },
      { cve_id: "CVE-2024-67890", description: "Privilege escalation bug in Linux Kernel.", cvss_score: 8.5, product: "Linux Kernel", published_at: "2024-03-12 09:30 AM" },
      { cve_id: "CVE-2024-34567", description: "SQL injection flaw in MySQL.", cvss_score: 7.2, product: "MySQL Database", published_at: "2024-03-11 04:20 PM" },
      { cve_id: "CVE-2024-98765", description: "Zero-day vulnerability affecting Windows Defender.", cvss_score: 9.0, product: "Windows Defender", published_at: "2024-03-11 02:10 PM" },
      { cve_id: "CVE-2024-11111", description: "Memory corruption bug in Google Chrome.", cvss_score: 7.8, product: "Google Chrome", published_at: "2024-03-10 11:15 AM" }
  ];

  function truncateString(str, threshold) {
    if (str.length <= threshold) {
      return str;
    } else {
      return str.slice(0, threshold) + "...";
    }
  }

  const cveRows = newCves.map(cve => `
    <tr>
      <td style="padding: 8px; border: 1px solid #444;">${cve.cve_id}</td>
      <td style="padding: 8px; border: 1px solid #444;">${truncateString(cve.description, 30)}</td>
      <td style="padding: 8px; border: 1px solid #444; font-weight: bold; color: ${cve.cvss_score > 8 ? 'red' : 'orange'};">
        ${cve.cvss_score === null ? "N/A" : cve.cvss_score}
      </td>
      <td style="padding: 8px; border: 1px solid #444;">${truncateString(cve.product, 20)}</td>
      <td style="padding: 8px; border: 1px solid #444;">${cve.published_at}</td>
    </tr>
  `).join("");

  return `
  <div style="background: url('https://img.freepik.com/free-photo/illustration-geometric-shapes-with-colorful-laser-lights_181624-26467.jpg?t=st=1742457374~exp=1742460974~hmac=58f5691d56b549fa5dc87ec3e4aeea65497813c183e86a0701f989c37983a22c&w=1800') no-repeat center center; background-size: cover; background-color: #001133; color: white; padding: 20px; text-align: center; font-family: Arial, sans-serif;">
    
    <!-- 🔥 Alert Banner -->
    <div style="background: rgba(200, 0, 0, 0.9); padding: 12px; font-size: 18px; font-weight: bold; text-align: center; color: white; text-transform: uppercase;">
      Critical Security Alert – Immediate Action Required
    </div>

    <div style="max-width: 550px; width: 90%; margin: 0 auto; background: rgba(0, 11, 43, 0.9); padding: 20px; border-radius: 10px;">
      
      <!-- Logo -->
      <div style="text-align: center; padding-bottom: 10px;">
        <img src="https://static.wixstatic.com/media/e48a18_c949f6282e6a4c8e9568f40916a0c704~mv2.png/v1/crop/x_0,y_151,w_1920,h_746/fill/w_310,h_120,fp_0.50_0.50,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/For%20Dark%20Theme.png" alt="DeepCytes Logo" width="100" style="display: block; margin: 0 auto;">
      </div>

      <!-- Alert Header -->
      <h1 style="color: #ffffff; font-size: 22px; font-family: 'Playfair Display', serif;">🚨 CVE Alert</h1>
      <p style="color: #d0d0d0;">New critical vulnerabilities have been detected.</p>

      <!-- 📊 Stats Overview (Fixed for Mobile) -->
      <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 400px; margin-top: 20px;">
        <div style="background: rgba(255, 140, 0, 0.8); padding: 5px; border-radius: 8px; color: black; width: 100%; max-width: 220px;">
          <h2 style="margin: 0;">${newCves.length}</h2>
          <p style="margin: 5px 0; font-weight: bold;">New CVEs Detected</p>
        </div>
        <div style="background: rgba(200, 0, 0, 0.9); padding: 5px; border-radius: 8px; color: white; width: 100%; max-width: 220px;">
          <h2 style="margin: 0;">${newCves.filter(cve => cve.cvss_score > 8).length}</h2>
          <p style="margin: 5px 0; font-weight: bold;">High-Risk CVEs (Score > 8.0)</p>
        </div>
      </div>

      <!-- CVE Details Table -->
      <div style="margin-top: 25px; background: rgba(26, 43, 77, 0.8); padding: 12px; border-radius: 10px;">
        <h2 style="font-size: 18px; font-family: 'Playfair Display', serif; text-align: center;">CVE Breakdown</h2>
        <table align="center" width="100%" style="border-collapse: collapse; color: white;">
          <tr style="background: rgba(38, 61, 109, 0.9); color: white;">
            <th style="padding: 10px; border: 1px solid #666;">CVE ID</th>
            <th style="padding: 10px; border: 1px solid #666;">Description</th>
            <th style="padding: 10px; border: 1px solid #666;">Score</th>
            <th style="padding: 10px; border: 1px solid #666;">Product</th>
            <th style="padding: 10px; border: 1px solid #666;">Timestamp</th>
          </tr>
          ${cveRows}
        </table>
      </div>

      <!-- Actions & Recommendations -->
      <div style="margin-top: 25px; background: rgba(26, 43, 77, 0.8); padding: 15px; border-radius: 10px;">
        <h2 style="font-size: 18px; font-family: 'Playfair Display', serif; text-align: center;">Recommendations</h2>
        <p style="text-align: center; font-size: 14px; color: #d0d0d0;">
          ✅ Patch affected systems immediately. <br>
          ⚠️ Prioritize vulnerabilities with CVSS score > 8.0. <br>
          🔍 Review vendor advisories and updates.
        </p>
      </div>

      <!-- CTA Button -->
      <div style="margin-top: 30px; text-align: center;">
        <a href="#" style="background: white; color: black; padding: 12px 20px; font-size: 14px; text-decoration: none; font-weight: bold; border-radius: 6px; display: inline-block;">🔎 View Full Report</a>
      </div>
    </div>
  </div>
  `;
}

module.exports = { getAlertEmail };
