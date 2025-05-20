const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');

// Function to generate PDF from audit data
const generateAuditPDF = (auditData, callback) => {
  // Create a new PDF document
  const doc = new PDFDocument({
    margin: 50,
    size: 'A4'
  });
  
  // Set up the PDF content
  setupDocument(doc, auditData);
  
  // Get the PDF as a buffer
  const chunks = [];
  doc.on('data', (chunk) => chunks.push(chunk));
  doc.on('end', () => callback(Buffer.concat(chunks)));
  
  // Finalize the PDF
  doc.end();
};

// Function to generate a zip file with separate PDFs for each product
// Modify the generateProductPDFsZip function to include a summary report
const generateProductPDFsZip = (auditData, outputPath, callback) => {
  // Extract unique products from matched vulnerabilities
  const uniqueProducts = new Set();
  
  if (auditData.matchedVulnerabilities) {
    auditData.matchedVulnerabilities.forEach(item => {
      if (item.matched_products) {
        item.matched_products.forEach(product => {
          uniqueProducts.add(product);
        });
      }
    });
  }
  
  // Create a temporary directory for PDFs
  const tempDir = path.join(__dirname, 'temp_pdfs');
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir);
  }
  
  // Create a zip archive
  const output = fs.createWriteStream(outputPath);
  const archive = archiver('zip', {
    zlib: { level: 9 } // Compression level
  });
  
  // Pipe archive data to the output file
  archive.pipe(output);
  
  // Counter for tracking completed PDFs
  let completedPDFs = 0;
  // Add 1 to total for the summary report
  const totalProducts = uniqueProducts.size + 1;
  
  // Create a summary report PDF
  const summaryPDF = new PDFDocument({
    margin: 50,
    size: 'A4'
  });
  
  const summaryPdfPath = path.join(tempDir, 'REPORT_SUMMARY.pdf');
  const summaryStream = fs.createWriteStream(summaryPdfPath);
  
  summaryPDF.pipe(summaryStream);
  
  // Set up the summary document
  setupSummaryDocument(summaryPDF, auditData);
  
  // Finalize the summary PDF
  summaryPDF.end();
  
  summaryStream.on('finish', () => {
    // Add summary PDF to zip archive as the first file
    archive.file(summaryPdfPath, { name: 'ADT_REPORT_SUMMARY.pdf' });
    
    completedPDFs++;
    
    // If no products found, create an empty zip file with just the summary
    if (uniqueProducts.size === 0) {
      archive.finalize();
      return;
    }
    
    // Generate a PDF for each product
    uniqueProducts.forEach(productName => {
      // Create a filtered copy of audit data for this product
      const productAuditData = {
        ...auditData,
        matchedVulnerabilities: auditData.matchedVulnerabilities.filter(vuln => 
          vuln.matched_products && vuln.matched_products.includes(productName)
        ),
        cveDetails: auditData.cveDetails ? auditData.cveDetails.filter(entity => 
          entity.type === 'product' && entity.name === productName
        ) : []
      };
      
      // Create product-specific PDF
      const productPDF = new PDFDocument({
        margin: 50,
        size: 'A4'
      });
      
      // Create a PDF file for this product
      const sanitizedProductName = productName.replace(/[^a-z0-9]/gi, '_').toLowerCase();
      const pdfPath = path.join(tempDir, `${sanitizedProductName}.pdf`);
      const pdfStream = fs.createWriteStream(pdfPath);
      
      productPDF.pipe(pdfStream);
      
      // Set up the document with product-specific title
      setupProductDocument(productPDF, productAuditData, productName);
      
      // Finalize the PDF
      productPDF.end();
      
      pdfStream.on('finish', () => {
        // Add PDF to zip archive
        archive.file(pdfPath, { name: `${sanitizedProductName}.pdf` });
        
        completedPDFs++;
        
        // When all PDFs are added to the archive, finalize it
        if (completedPDFs === totalProducts) {
          archive.finalize();
        }
      });
    });
  });
  
  // Listen for archive finalization
  output.on('close', () => {
    // Clean up temp directory
    if (fs.existsSync(tempDir)) {
      fs.rmdirSync(tempDir, { recursive: true });
    }
    callback();
  });
  
  // Handle archive errors
  archive.on('error', (err) => {
    throw err;
  });
};

// Helper function to set up the summary document
// Helper function to set up the summary document with responsive table rows
const setupSummaryDocument = (doc, auditData) => {
  // Add document title in bold
  doc.font('Helvetica-Bold')
     .fontSize(24)
     .text('REPORT SUMMARY', {
       align: 'center'
     });
     
  doc.moveDown(1);
  
  // Add audit info
  doc.font('Helvetica-Bold')
     .fontSize(16)
     .text('Audit Information');
  
  doc.font('Helvetica')
     .fontSize(12)
     .text(`Audit ID: ${auditData._id || 'N/A'}`)
     .text(`Generated: ${new Date().toLocaleString()}`)
     .text(`Software Scanned: ${auditData.software?.length || 0}`);
  
  doc.moveDown(2);
  
  // Add software inventory section with match status
  doc.font('Helvetica-Bold')
     .fontSize(20)
     .text('Software Inventory Status', { align: 'center' });
  
  doc.moveDown(1);
  
  // Create a map to track all matched software
  const matchedSoftwareMap = new Map();
  
  if (auditData.matchedVulnerabilities) {
    auditData.matchedVulnerabilities.forEach(item => {
      // Store by software name for quick lookup
      matchedSoftwareMap.set(item.software_name.toLowerCase(), true);
    });
  }
  
  if (auditData.software && auditData.software.length > 0) {
    const tableTop = doc.y;
    const nameWidth = (doc.page.width - 100) * 0.7;
    const statusWidth = (doc.page.width - 100) * 0.3;
    
    // Draw table headers with border
    doc.lineWidth(1);
    doc.rect(50, tableTop - 5, doc.page.width - 100, 25).stroke();
    
    doc.font('Helvetica-Bold')
       .fontSize(12)
       .text('Software Name', 60, tableTop)
       .text('Match Status', 50 + nameWidth, tableTop);
    
    let rowY = tableTop + 25;
    
    // Draw table rows - showing software name and match status
    auditData.software.forEach(sw => {
      // Get software name (with fallback)
      const softwareName = sw.name || 'N/A';
      
      // Calculate height needed for this row
      // First, save the current doc position
      const currentY = doc.y;
      
      // Create a temporary document to measure text height
      const tempDoc = new PDFDocument();
      tempDoc.font('Helvetica').fontSize(12);
      
      // Measure the height of wrapped text with specified width
      const textHeight = Math.max(
        tempDoc.heightOfString(softwareName, { width: nameWidth - 10 }),
        tempDoc.heightOfString('Matched/Not Matched', { width: statusWidth - 10 })
      );
      tempDoc.end();
      
      // Determine row height with padding
      const rowHeight = Math.max(25, textHeight + 10); // Minimum 25px or text height + padding
      
      // Check if we need a new page
      if (rowY + rowHeight > doc.page.height - 50) {
        doc.addPage();
        
        // Redraw header on new page
        rowY = 50;
        
        doc.lineWidth(1);
        doc.rect(50, rowY - 5, doc.page.width - 100, 25).stroke();
        
        doc.font('Helvetica-Bold')
           .fontSize(12)
           .text('Software Name', 60, rowY)
           .text('Match Status', 50 + nameWidth, rowY);
        
        rowY += 25;
      }
      
      // Draw row with border and dynamic height
      doc.rect(50, rowY - 5, doc.page.width - 100, rowHeight).stroke();
      
      // Check if this software has any matches
      const isMatched = matchedSoftwareMap.has(softwareName.toLowerCase());
      const statusText = isMatched ? 'Matched' : 'Not Matched';
      const statusColor = isMatched ? '#007700' : '#770000';
      
      // Calculate vertical center position for text
      const textY = rowY + (rowHeight - textHeight) / 2 - 5;
      
      doc.font('Helvetica')
         .fontSize(12)
         .text(softwareName, 60, textY, { 
           width: nameWidth - 10, 
           ellipsis: true,
           lineBreak: true
         });
      
      // Use colored text for the status
      doc.fillColor(statusColor)
         .text(statusText, 50 + nameWidth, textY, { 
           width: statusWidth - 10,
           lineBreak: true
         });
      
      // Reset text color to black for next row
      doc.fillColor('black');
      
      rowY += rowHeight;
    });
  } else {
    doc.font('Helvetica')
       .text('No software inventory available.', { italic: true });
  }
  
  // Add summary counts
  doc.moveDown(2);
  doc.font('Helvetica-Bold')
     .fontSize(16)
     .text('Match Summary');
  
  doc.moveDown(0.5);
  
  const matchedCount = Array.from(matchedSoftwareMap.values()).filter(Boolean).length;
  const totalSoftware = auditData.software?.length || 0;
  const unmatchedCount = totalSoftware - matchedCount;
  
  // Display counts
  doc.font('Helvetica')
     .fontSize(12)
     .text(`Total Software Items: ${totalSoftware}`)
     .text(`Matched Software: ${matchedCount}`)
     .text(`Unmatched Software: ${unmatchedCount}`);
  
  // Calculate match percentage
  const matchPercentage = totalSoftware > 0 ? 
    ((matchedCount / totalSoftware) * 100).toFixed(1) : 0;
  
  doc.moveDown(0.5);
  doc.font('Helvetica-Bold')
     .text(`Match Rate: ${matchPercentage}%`);
};


// Helper function to set up the PDF document content
const setupDocument = (doc, auditData) => {
  // Add document title
  doc.font('Helvetica-Bold')
     .fontSize(24)
     .text('Software Vulnerability Audit Report', {
       align: 'center'
     });
     
  doc.moveDown(1);
  
  // Add audit info
  doc.font('Helvetica-Bold')
     .fontSize(16)
     .text('Audit Information');
  
  doc.font('Helvetica')
     .fontSize(12)
     .text(`Audit ID: ${auditData._id || 'N/A'}`)
     .text(`Generated: ${new Date().toLocaleString()}`)
     .text(`Software Scanned: ${auditData.software?.length || 0}`);
  
  doc.moveDown(2);
  
  // Add summary stats
  addSummaryStats(doc, auditData);
  
  // Add vulnerable products section
  addProductsSection(doc, auditData);
  
  // Add software inventory section
  addSoftwareSection(doc, auditData);
  
  // Add CVE details section
  addCVEDetailsSection(doc, auditData);
};

// Helper function for product-specific PDFs
const setupProductDocument = (doc, auditData, productName) => {
  // Add document title
  doc.font('Helvetica-Bold')
     .fontSize(24)
     .text(`Vulnerability Report: ${productName}`, {
       align: 'center'
     });
     
  doc.moveDown(1);
  
  // Add audit info
  doc.font('Helvetica-Bold')
     .fontSize(16)
     .text('Audit Information');
  
  doc.font('Helvetica')
     .fontSize(12)
     .text(`Audit ID: ${auditData._id || 'N/A'}`)
     .text(`Generated: ${new Date().toLocaleString()}`)
     .text(`Product: ${productName}`);
  
  doc.moveDown(2);
  
  // Add summary stats for this product only
  addSummaryStats(doc, auditData);
  
  // Add software inventory section if exists for this product
  const relevantSoftware = auditData.software?.filter(sw => 
    sw.name === productName || sw.publisher === productName
  );
  
  if (relevantSoftware && relevantSoftware.length > 0) {
    // Use only relevant software for this product
    const productSpecificData = {
      ...auditData,
      software: relevantSoftware
    };
    addSoftwareSection(doc, productSpecificData);
  }
  
  // Add CVE details section only for this product
  addCVEDetailsSection(doc, auditData);
};

// Add summary statistics
const addSummaryStats = (doc, auditData) => {
  // Count total CVEs from the cveDetails
  const totalCVEs = auditData.cveDetails?.reduce((total, entity) => {
    return total + (entity.cves?.length || 0);
  }, 0) || 0;
  
  // Get current year for recent CVE calculation
  const currentYear = new Date().getFullYear();
  
  // Count recent CVEs (from current year)
  const recentCVEs = auditData.cveDetails?.reduce((count, entity) => {
    return count + (entity.cves?.filter(cve => 
      cve.published_date && new Date(cve.published_date).getFullYear() === currentYear
    ).length || 0);
  }, 0) || 0;
  
  // Count high risk CVEs (CVSS >= 7)
  const highRiskCVEs = auditData.cveDetails?.reduce((count, entity) => {
    return count + (entity.cves?.filter(cve => cve.cvss_score >= 7).length || 0);
  }, 0) || 0;
  
  // Count medium risk CVEs (CVSS >= 4 and < 7)
  const mediumRiskCVEs = auditData.cveDetails?.reduce((count, entity) => {
    return count + (entity.cves?.filter(cve => 
      cve.cvss_score >= 4 && cve.cvss_score < 7
    ).length || 0);
  }, 0) || 0;
  
  // Count low risk CVEs (CVSS < 4)
  const lowRiskCVEs = auditData.cveDetails?.reduce((count, entity) => {
    return count + (entity.cves?.filter(cve => cve.cvss_score < 4).length || 0);
  }, 0) || 0;
  
  doc.font('Helvetica-Bold')
     .fontSize(16)
     .text('CVE Summary');
  
  doc.moveDown(0.5);
  
  // Create a simple table for summary stats
  const tableTop = doc.y;
  const colWidth = (doc.page.width - 100) / 2;
  
  doc.font('Helvetica-Bold').fontSize(12);
  doc.text('Total CVEs:', 50, tableTop);
  doc.font('Helvetica').text(totalCVEs.toString(), 50 + colWidth, tableTop);
  
  doc.font('Helvetica-Bold');
  doc.text('Recent CVEs:', 50, tableTop + 20);
  doc.font('Helvetica').text(recentCVEs.toString(), 50 + colWidth, tableTop + 20);
  
  doc.font('Helvetica-Bold');
  doc.text('High Risk CVEs:', 50, tableTop + 40);
  doc.font('Helvetica').text(highRiskCVEs.toString(), 50 + colWidth, tableTop + 40);
  
  doc.font('Helvetica-Bold');
  doc.text('Medium Risk CVEs:', 50, tableTop + 60);
  doc.font('Helvetica').text(mediumRiskCVEs.toString(), 50 + colWidth, tableTop + 60);
  
  doc.font('Helvetica-Bold');
  doc.text('Low Risk CVEs:', 50, tableTop + 80);
  doc.font('Helvetica').text(lowRiskCVEs.toString(), 50 + colWidth, tableTop + 80);
  
  doc.moveDown(5);
};

// Add products section - SIMPLIFIED
const addProductsSection = (doc, auditData) => {
  doc.addPage();
  doc.font('Helvetica-Bold')
     .fontSize(20)
     .text('Vulnerable Products', { align: 'center' });
  
  doc.moveDown(1);
  
  // Extract products from matched vulnerabilities
  const allProducts = new Map();
  
  if (auditData.matchedVulnerabilities) {
    auditData.matchedVulnerabilities.forEach(item => {
      if (item.matched_products) {
        item.matched_products.forEach(product => {
          allProducts.set(product, (allProducts.get(product) || 0) + 1);
        });
      }
    });
  }
  
  // Sort products by count
  const sortedProducts = Array.from(allProducts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);
  
  // Draw products table - Simple approach
  if (sortedProducts.length > 0) {
    const tableTop = doc.y;
    const colWidth = (doc.page.width - 100) / 2;
    
    // Draw simple table headers with border
    doc.lineWidth(1);
    doc.rect(50, tableTop - 5, doc.page.width - 100, 25).stroke();
    
    doc.font('Helvetica-Bold')
       .fontSize(12)
       .text('Product Name', 60, tableTop)
       .text('Vulnerability Count', 50 + colWidth, tableTop);
    
    let rowY = tableTop + 25;
    
    // Draw table rows - simple approach
    sortedProducts.forEach((product, i) => {
      // Check if we need a new page
      if (rowY > doc.page.height - 100) {
        doc.addPage();
        
        // Redraw header on new page
        rowY = 50;
        
        doc.lineWidth(1);
        doc.rect(50, rowY - 5, doc.page.width - 100, 25).stroke();
        
        doc.font('Helvetica-Bold')
           .fontSize(12)
           .text('Product Name', 60, rowY)
           .text('Vulnerability Count', 50 + colWidth, rowY);
        
        rowY += 25;
      }
      
      // Draw simple row with border
      doc.rect(50, rowY - 5, doc.page.width - 100, 25).stroke();
      
      doc.font('Helvetica')
         .fontSize(12)
         .text(product.name, 60, rowY)
         .text(product.count.toString(), 50 + colWidth, rowY);
      
      rowY += 25;
    });
  } else {
    doc.font('Helvetica')
       .text('No vulnerable products found.', { italic: true });
  }
};

// Add software inventory section - SIMPLIFIED
const addSoftwareSection = (doc, auditData) => {
  doc.addPage();
  doc.font('Helvetica-Bold')
     .fontSize(20)
     .text('Software Inventory', { align: 'center' });
  
  doc.moveDown(1);
  
  if (auditData.software && auditData.software.length > 0) {
    const tableTop = doc.y;
    const nameWidth = (doc.page.width - 100) * 0.4;
    const versionWidth = (doc.page.width - 100) * 0.3;
    const publisherWidth = (doc.page.width - 100) * 0.3;
    
    // Draw simple table headers with border
    doc.lineWidth(1);
    doc.rect(50, tableTop - 5, doc.page.width - 100, 25).stroke();
    
    doc.font('Helvetica-Bold')
       .fontSize(12)
       .text('Name', 60, tableTop)
       .text('Version', 50 + nameWidth, tableTop)
       .text('Publisher', 50 + nameWidth + versionWidth, tableTop);
    
    let rowY = tableTop + 25;
    
    // Draw table rows - simple approach
    auditData.software.forEach((sw, i) => {
      // Check if we need a new page
      if (rowY > doc.page.height - 100) {
        doc.addPage();
        
        // Redraw header on new page
        rowY = 50;
        
        doc.lineWidth(1);
        doc.rect(50, rowY - 5, doc.page.width - 100, 25).stroke();
        
        doc.font('Helvetica-Bold')
           .fontSize(12)
           .text('Name', 60, rowY)
           .text('Version', 50 + nameWidth, rowY)
           .text('Publisher', 50 + nameWidth + versionWidth, rowY);
        
        rowY += 25;
      }
      
      // Draw simple row with border
      doc.rect(50, rowY - 5, doc.page.width - 100, 25).stroke();
      
      doc.font('Helvetica')
         .fontSize(12)
         .text(sw.name || 'N/A', 60, rowY, { width: nameWidth - 10, ellipsis: true })
         .text(sw.version || 'N/A', 50 + nameWidth, rowY, { width: versionWidth - 10, ellipsis: true })
         .text(sw.publisher || 'N/A', 50 + nameWidth + versionWidth, rowY, { width: publisherWidth - 10, ellipsis: true });
      
      rowY += 25;
    });
  } else {
    doc.font('Helvetica')
       .text('No software inventory available.', { italic: true });
  }
};

// Add CVE details section - KEEPING THE ENHANCED DESIGN
const addCVEDetailsSection = (doc, auditData) => {
  if (!auditData.cveDetails || auditData.cveDetails.length === 0) {
    return;
  }
   
  // Filter to include only product entities
  const productEntities = auditData.cveDetails.filter(entity => entity.type === 'product');
   
  if (productEntities.length === 0) {
    return;
  }
   
  // Group CVEs by entity (only products now)
  productEntities.forEach((entity, entityIndex) => {
    // Start each entity on a new page
    doc.addPage();
       
    // Add header for the entity
    doc.rect(50, 50, doc.page.width - 100, 40)
       .fillAndStroke('#333333', '#000000');
       
    doc.fillColor('white')
       .font('Helvetica-Bold')
       .fontSize(16)
       .text(`Product: ${entity.name}`, 60, 65);
       
    doc.fillColor('black');
    let yPos = 110;
       
    if (entity.cves && entity.cves.length > 0) {
      entity.cves.forEach((cve, cveIndex) => {
        // Check if we need a new page
        if (yPos > doc.page.height - 200) {
          doc.addPage();
          yPos = 50;
        }
               
        // Draw CVE card
        const cardHeight = calculateCVECardHeight(doc, cve);
               
        // Determine severity color
        const severityColor = getSeverityColor(cve.cvss_score);
               
        // Draw card background
        doc.rect(50, yPos, doc.page.width - 100, cardHeight)
           .fillAndStroke('#f8f8f8', '#cccccc');
               
        // Draw severity indicator
        doc.rect(50, yPos, 10, cardHeight)
           .fill(severityColor);
               
        // Draw CVE ID with background - Darker background for better visibility
        doc.rect(60, yPos, doc.page.width - 110, 25)
           .fillAndStroke('#444444', '#333333');
               
        // Display CVE ID in white text for better visibility against dark background
        doc.fillColor('white')
           .font('Helvetica-Bold')
           .fontSize(14);
        
        // Store the current position for the link
        const textX = 70;
        const textY = yPos + 6;
        const cveId = cve.cve_id || 'Unknown CVE';
        
        // Add a clickable link to the CVE ID without showing the URL
        // The full URL will be: http://dccveengine-vm.eastus.cloudapp.azure.com/cve/{CVE-ID}
        if (cve.cve_id) {
          const cveLink = `http://dccveengine-vm.eastus.cloudapp.azure.com/cve/${cve.cve_id}`;
          
          // Calculate the approximate width of the CVE ID text
          const textWidth = doc.widthOfString(cveId);
          const textHeight = 16; // Approximate height of the text
          
          // Add the link annotation that will be clickable
          doc.link(textX, textY, textWidth, textHeight, cveLink);
        }
        
        // Now add the text (will appear over the link area)
        doc.text(cveId, textX, textY);
               
        // Reset text color to black for remaining content
        doc.fillColor('black');
               
        // Draw CVE metadata
        let metadataY = yPos + 35;
               
        // Draw CVSS score with colored badge
        const cvssWidth = 80;
        const cvssX = 70;
        doc.rect(cvssX, metadataY, cvssWidth, 20)
           .fillAndStroke(severityColor, severityColor);
               
        doc.fillColor('white')
           .fontSize(10)
           .text(`CVSS: ${cve.cvss_score}`, cvssX + 5, metadataY + 5);
               
        // Draw EPSS score with colored badge
        const epssWidth = 80;
        const epssX = cvssX + cvssWidth + 10;
        const epssColor = getEPSSColor(cve.epss_score);
               
        doc.rect(epssX, metadataY, epssWidth, 20)
           .fillAndStroke(epssColor, epssColor);
               
        doc.fillColor('white')
           .text(`EPSS: ${formatEPSSScore(cve.epss_score)}`, epssX + 5, metadataY + 5);
               
        // Draw published date
        doc.fillColor('black')
           .text(`Published: ${cve.published_date}`, cvssX + cvssWidth + epssWidth + 20, metadataY + 5);
               
        // Draw description
        doc.font('Helvetica')
           .fontSize(11)
           .text('Description:', 70, metadataY + 30);
               
        doc.font('Helvetica')
           .fontSize(10)
           .text(cve.description || 'No description available', 70, metadataY + 50, {
             width: doc.page.width - 140,
             align: 'justify'
           });
               
        yPos += cardHeight + 15;
      });
    } else {
      doc.font('Helvetica')
         .text('No CVEs found for this entity.', { italic: true });
    }
  });
};

// Helper functions for CVE details section
const calculateCVECardHeight = (doc, cve) => {
  // Calculate height needed for description
  const textWidth = doc.page.width - 140;
  const descriptionText = cve.description || 'No description available';
  
  // Create temporary doc to measure text height
  const temp = new PDFDocument();
  temp.fontSize(10);
  
  const textHeight = temp.heightOfString(descriptionText, {
    width: textWidth,
    align: 'justify'
  });
  
  temp.end();
  
  // Base height (header + metadata) + description height + padding
  return Math.max(130, 90 + textHeight);
};

const getSeverityColor = (cvssScore) => {
  if (!cvssScore || cvssScore === 'N/A') return '#8A8A8A';
  if (cvssScore >= 9) return '#FF0000';
  if (cvssScore >= 7) return '#FF8800';
  if (cvssScore >= 4) return '#FFCC00';
  return '#00CC00';
};

const getEPSSColor = (epssScore) => {
  if (!epssScore || epssScore === 'N/A') return '#8A8A8A';
  
  const score = parseFloat(epssScore);
  if (isNaN(score)) return '#8A8A8A';
  
  if (score * 100 >= 0.09) return '#FF0000';
  if (score * 100 >= 0.05) return '#FF8800';
  return '#00CC00';
};

const formatEPSSScore = (epssScore) => {
  if (!epssScore || epssScore === 'N/A') return 'N/A';
  
  const score = parseFloat(epssScore);
  if (isNaN(score)) return 'N/A';
  
  // Format as percentage with 2 decimal places
  return `${(score * 100).toFixed(2)}%`;
};

module.exports = { 
  generateAuditPDF,
  generateProductPDFsZip
};