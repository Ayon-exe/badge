const logger = require("../logger");
const fs = require("fs");
const path = require("path");
const csv = require("csv-parser");
const nodemailer = require("nodemailer");

const { spawn } = require("child_process");

const createUsersModel = (db) => db.collection("users");
const createWatchlistModel = (db) => db.collection("watchlist");

const { getAlertEmail } = require("../emailTemplates/AlertEmail");

const { getWeeklyMonthlyEmail } = require("../emailTemplates/WeeklyMonthlyEmail");

const { getUpdateEmail } = require('../emailTemplates/UpdateEmail');
const { getActionEmail } = require('../emailTemplates/ActionEmail');
const { getTodaysActivityEmail } = require('../emailTemplates/TodaysActivity');

const {
  getNewCVEs,
  getWeeklyMonthlyData,
  getUpdateData,
getTodaysActivityData,
} = require("../controllers/emailController");

async function generateCsvData(outputFile) {
  const repo = process.env.ASSETS + "cvelistV5";
  const scriptPath = "./utils/updates.sh"; // Specify the path to your shell script

  // Execute the shell script with the input file path
  try {
    await new Promise((resolve, reject) => {
      logger.info(
        `Executing command: bash ${scriptPath} ${repo} ${outputFile}`
      );
      const child = spawn("bash", [scriptPath, repo, outputFile]);

      let stdout = "";
      let stderr = "";

      // Capture standard output
      child.stdout.on("data", (data) => {
        stdout += data.toString();
        logger.debug(`Script Stdout: ${stdout}`);
      });

      // Capture standard error
      child.stderr.on("data", (data) => {
        stderr += data.toString();
        logger.error(`Script Stderr: ${stderr}`);
      });

      // Handle process exit
      child.on("exit", (code) => {
        if (code !== 0) {
          logger.error(`Error executing script: ${stderr}`);
          return reject(`Error executing script: ${stderr}`);
        }
        logger.debug(stdout);
        resolve(stdout);
      });

      // Handle errors in spawning the process
      child.on("error", (err) => {
        logger.error(`Failed to start script: ${err.message}`);
        reject(`Failed to start script: ${err.message}`);
      });
    });
    logger.info("updates Generated.");
  } catch (error) {
    logger.error("Error processing updates :", error);
  }
}

async function extractVendorWithMetadata(db, outputFile) {
  // Read output.csv with columns (status, CVE-ID)
  const data = await readCsvFile(outputFile);

  logger.debug("CSV Data: " + data.length);
  logger.debug(
    "Sample object in data: [" + data[0].stat + "," + data[0].CVE_ID + "]"
  );

  // Initialize an object to store vendor metadata
  const vendorMetadata = {};

  // Iterate through each row in the data
  for (const row of data) {
    const { stat: stat, CVE_ID: cveId } = row;
    logger.debug(`status: ${stat}, CVE_ID: ${cveId} `);

    // Query the database for the vendor name
    const vendorName = await getVendorNameFromDb(db, cveId);

    // Check if the vendor name exists in the vendorMetadata object
    if (vendorMetadata[vendorName]) {
      // If the status is 'A', increment the 'A' count
      if (stat === "A") {
        vendorMetadata[vendorName].A++;
      }
      // If the stat is 'M', increment the 'M' count
      else if (stat === "M") {
        vendorMetadata[vendorName].M++;
      }
    } else {
      // If the vendor name doesn't exist, add it to the vendorMetadata object
      vendorMetadata[vendorName] = {
        A: stat === "A" ? 1 : 0,
        M: stat === "M" ? 1 : 0,
      };
    }
  }

  logger.debug(vendorMetadata);

  return vendorMetadata;
}

// Helper functions
async function readCsvFile(filePath) {
  return new Promise((resolve, reject) => {
    logger.debug(`Rading csv: ${filePath}`);
    const data = [];
    fs.createReadStream(filePath)
      .pipe(csv())
      .on("data", (row) => data.push(row))
      .on("end", () => resolve(data))
      .on("error", (err) => reject(err));
  });
}

async function getVendorNameFromDb(db, cveId) {
  const cveCollection = db.collection("cves");
  try {
    const result = await cveCollection.findOne({ cve_id: cveId });
    logger.debug(result);
    if (result && result.cpe_data && result.cpe_data[0]) {
      return result.cpe_data[0].vendor;
    } else {
      return null;
    }
  } catch (err) {
    logger.error("Error querying the database:", err);
    throw err;
  }
}

// helper for sendAlertEmail function
function addProductField(data) {
  try {
  const uniqueProducts = new Set();
  data.forEach(item => {
    if (Array.isArray(item.cpe)) {
      item.cpe.forEach(cpeItem => {
        uniqueProducts.add(cpeItem.product);
      });
    } else {
      uniqueProducts.add(item.cpe.product);
    }
  });

  return data.map(item => {
    let productString;
    if (Array.isArray(item.cpe)) {
      const uniqueProductCount = uniqueProducts.size - item.cpe.length;
      productString = item.cpe.map(cpeItem => {
        return uniqueProductCount > 0 ? `${cpeItem.product} (${uniqueProductCount})` : cpeItem.product;
      }).join(', ');
    } else {
      const uniqueProductCount = uniqueProducts.size - 1;
      productString = uniqueProductCount > 0 ? `${item.cpe.product} (${uniqueProductCount})` : item.cpe.product;
    }
    return {
      ...item,
      product: productString
    };
  });
  } catch(e) {
    logger.error(e)
  }
}


//Completing the alert mail process
async function sendAlertEmail(db, username, email) {
  try { 
    const data = await getNewCVEs(db, username);
    if (data.length > 0 ){
    const modified_data = addProductField(data)
    const html = getAlertEmail(modified_data);
    const subject = "CVE Alert";

    await sendMail(username, email, subject, html)
  
    logger.info("CVE Alert sent");
    logger.info(`EMAIL: data: ${JSON.stringify(modified_data)} alert email`);
    } else {
    logger.info(`EMAIL: No new cves found for ${username}`);
    }
    logger.error(`EMAIL: data: ${data} alert email`);
  } catch (e) {
    logger.error(`EMAIL: Something went wrong, ${username} alert email`);
    console.error(e);
  }

}

//Completing the monthly mail process
async function sendMonthlyEmail(db, username, email) {
  try {
    const data = await getWeeklyMonthlyData(db, username);
    const html = getWeeklyMonthlyEmail(data);
    const subject = "Monthly CVE Report";
    await sendMail(username, email, subject, html)
    logger.info(`Monthly Email sent to ${username}`);
    logger.error(`EMAIL: data: ${data} monthly email`);
  } catch (e) {
    logger.error(`EMAIL: Something went wrong, ${username} monthly email`);
    console.error(e);
  }
}

//Completing the weekly monthly mail process
async function sendWeeklyMonthlyEmail(db, username, email) {
  try {
    const data = await getWeeklyMonthlyData(db, username);
    const html = getWeeklyMonthlyEmail(data);
    const subject = "Weekly CVE Report";
    await sendMail(username, email, subject, html)
    logger.info(`Weekly Email sent to ${username}`);
    logger.error(`EMAIL: data: ${data} monthly email`);
  } catch (e) {
    logger.error(`EMAIL: Something went wrong, ${username} monthly email`);
    console.error(e);
  }
}
  
//Completing the Updats mail process
async function sendUpdateEmail(db, username, email) {
  try {
    const data = await getUpdateData(db, username);
    const html = getUpdateEmail(data);
    const subject = "CVE Update";
    await sendMail(username, email, subject, html)
    logger.info("Update Email sent");
    logger.error(`EMAIL: data: ${data} monthly email`);
  } catch (e) {
    logger.error(`EMAIL: Something went wrong, ${username} monthly email`);
    console.error(e);
  }
}

//Completing the Todays Activity email process
async function sendTodaysActivityEmail(db, username, email) {
  try {
    const data = await getTodaysActivityData(db, username);
    const html = getTodaysActivityEmail(data);
    const subject = "Todays Activiy";
    await sendMail(username, email, subject, html)
    logger.info("Update Email sent");
    logger.error(`EMAIL: data: ${data} Todays email`);
  } catch (e) {
    logger.error(`EMAIL: Something went wrong, ${username} Todays email`);
    console.error(e);
  }
}

async function sendAction(db, username, msg) {
  try {
    const query = { name: username };

    const users = createUsersModel(db);
    const user = await users.findOne(query);
    const email = await user.email;

    const html = getActionEmail({msg});

    const subject = "Watchlist Alert";

    await sendMail(username, email, subject, html)
    logger.info("Email sent");
    logger.error(`EMAIL: data: ${data} monthly email`);
  } catch (e) {
    logger.error(`EMAIL: Something went wrong, ${username} monthly email`);
    console.error(e);
  }
}


// Incomplete
async function parseUpdates(db, updates) {
  // Get the users collection
  const users = createUsersModel(db);
  const watchlistCollection = createWatchlistModel(db);

  try {
    // Fetch all watchilst from the collection and make a single list of 
    const watchlistArray = await watchlistCollection.find().toArray();

    // backward compatible watchlist transformation;
    function transfromWatchlist(watchlistObject){
      const watchlist = {}
      // add username
      watchlist.username = watchlistObject.username;
      // set of products and vendors
      const uniqueItems = new Set();
      // iterate over each watchlist 
      for ( list of watchlistObject.watchlists ){

        for ( item of list.items ){
        // adding each item to a set
          uniqueItems.add(item);
        }
      }
       
      // converting and returning the set as an array
      watchlist.watching = [...uniqueItems];
      return watchlist;
    }


    let batchNotification = [];
    for (const watchlistObject of watchlistArray) {

      const watchlist = transfromWatchlist(watchlistObject);

      //email, username, A, M
      const username = watchlist.username;


      const query = { name: watchlist.username };
      const user = await users.findOne(query);
      const email = user.email;

      sendWeeklyMonthlyEmail(db, username, email);
      sendAlertEmail(db, username, email);
      sendUpdateEmail(db, username, email);

      // let A = 0;
      // let M = 0;
      // watching = watchlist.watching;
      // watching.forEach((element) => {
      //   if (updates[element]) {
      //     A += updates[element].A;
      //     M += updates[element].M;
      //   }
      // });
      // notification = {
      //   username: username,
      //   email: email,
      //   A: A,
      //   M: M,
      // };
      // // batchNotification.push(notification);
      // // await notify(username, email, A, M);
      // logger.info(A);
      // logger.info(M);
      // // console.log({ "arrayOfNotfication": batchNotification });
    }
    // return batchNotification;
  } catch (error) {
    console.error("Error fetching users:", error);
  }
}
  
// Mock-up for the notify function
function notify(username, email, A, M) {
  // Your custom logic for notifying the user (e.g., send an email or log it)
  // Create a transporter object
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER, // Your Gmail address from the .env file
      pass: process.env.EMAIL_PASS, // Your App Password from the .env file
    },
  });

  // Read the Handlebars template from a file
  // const source = fs.readFileSync('email-temp.hbs', 'utf8');
  // const template = handlebars.compile(source);

  // Render the template with the dynamic data
  // const htmlTemplate = template(data);
  let htmlTemplate =
    `<p style="font:12px;color:grey">` +
    "Hi" +
    '<span sytle="font:18px"><i>' +
    username +
    "</i></span>";
  if (A > 0 && M > 0) {
    htmlTemplate += `Your watchlist has a update of ${A} newly added CVE's and ${M} modified CVE's.</p>`;
  } else if (A > 0) {
    htmlTemplate += `Your watchlist has a update of ${A} newly added CVE's.</p>`;
  } else if (M > 0) {
    htmlTemplate += `Your watchlist has a update of ${M} modified CVE's.</p>`;
  } else {
    return 0;
  }

  htmlTemplate += `<p><i>For more info visit your watchlist page</i></p>`;

  // Define the email options
  const mailOptions = {
    from: process.env.FROM_EMAIL, // Sender's email
    to: email,
    subject: "Automated Email Notification",
    html: htmlTemplate,
  };

  // logger.info("notifying...");
  // console.log(email);
  // console.log(htmlTemplate);

  // Send the email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
  logger.debug(`Notification sent to ${username} (${email}): A=${A}, M=${M}`);
}

function sendMail(username, email , subject, htmlTemplate) {
  // Create a transporter object
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER, // Your Gmail address from the .env file
      pass: process.env.EMAIL_PASS, // Your App Password from the .env file
    },
  });

  // Define the email options
  const mailOptions = {
    from: process.env.FROM_EMAIL, // Sender's email
    to: email,
    subject,
    html: htmlTemplate,
    // attachments: [
    //         {
    //             filename: 'deepcytes_logo.png', // The name of the image file
    //             path: path.join(__dirname, '../public/deepcytes_logo.png'), // Path to the image
    //             cid: 'deecytes_logo' // Same cid value as in the html img src
    //         }
    //     ]
  };

  // logger.info("notifying...");
  // console.log(email);
  // console.log(htmlTemplate);

  // Send the email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
  // logger.debug(`Notification sent to ${username} (${email}): A=${A}, M=${M}`);
}
  
// async function extractVendorWithMetadata(outputFile) {
//
//     // Read output.csv with columns (status, CVE-ID)
//     // for each row
//         //query db for vendorName
//
//         //if vendor exist in []
//             //if status = 'A'
//                 //[].vendorName.A += 1;
//
//             //else if status = 'M'
//                 //[].vendorName.M += 1;
//
//         //else
//             /*
//             [].add (
//                 vendorName: {
//                     A: 0,
//                     M: 0
//                 }
//             )
//             */
module.exports = {
  generateCsvData,
  parseUpdates,
  notify,
  extractVendorWithMetadata,
  sendAction,
  sendAlertEmail,
  sendWeeklyMonthlyEmail,
  sendUpdateEmail,
  sendTodaysActivityEmail,
};

