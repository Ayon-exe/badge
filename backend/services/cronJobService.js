// cron/cronJobs.js
const cron = require('node-cron');
const { checkGitDiff } = require("./gitdiff"); // Import checkGitDiff
const { parseCVEMapData, processChangedFilesCvemap } = require("./cvemapService");
const { cloneOrPullRepo } = require("./git"); // Import parseCVEMapData
const { parseNVDData } = require("./nvdServices"); // Import parseNVDData
const { parseUnifiedData } = require("./unified"); // Import parseUnifiedData
const { cloneOrUpdateMITRERepo, parseCVEData } = require('./mitreService');
const connectDB = require('../config/db');
const { updateSearchCollection } = require("./searchService"); // Import checkGitDiff
const { 
    updateCWEHomeStats, 
    updateCVSSHomeStats,
} = require("./graphService"); // Import checkGitDiff
const {
  sendAlertEmail,
  sendWeeklyMonthlyEmail,
  sendMonthlyEmail,
  sendUpdateEmail,
  sendTodaysActivityEmail,
} = require("./watchlistService");
const {
  updateBoxDataStats,
  updateProductsBoxDataStats,
  updateVendorsBoxDataStats,
  updateCWEStats, 
  updateCvssScoreRanges,
  updateExploitedStats,
  updateFixesStats,
  updateTopVendorStats,
  updateCVEStats,
} = require("../controllers/cveController"); // Import checkGitDiff
const logger = require('../logger');
const createUsersModel = (db) => db.collection("users");
const createWatchlistModel = (db) => db.collection("watchlist");

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
       
const DataUpdateCronString   = '45 * * * *';
const NVDDataUpdateCronString = '0 */2 * * *';
//28th date of every month at 11 am 
const emailMonthlyCronString = '0 11 28 * *';
// 6th day of every week ( i.e. Saturday ) at 10am
const emailWeeklyCronString  = '0 10 * * 6';
// at 9 am in the monring everyday
const emailUpdateCronString  = '0 9 * * *';
// at 8am in the morning and 8pm (i.e. 20hrs) in the evening everyday
const emailTodaysActivityCronString = '0 20 * * *';

const nvdCron = cron.schedule(DataUpdateCronString, async () => {
  //NVD
  logger.info('Running NVD data parsing...');
  try {
    await parseNVDData(db);
    logger.info('NVD data parsing completed successfully.');
  } catch (error) {
    logger.error(error);
    logger.error('Error during NVD data parsing:');
  }

});

const cronJob = cron.schedule(DataUpdateCronString, async () => {
    try{
        const db = await connectDB();
// MITRE
        logger.info('Running MITRE data processing and Git diff check...');
        try {
            // Check for Git differences
            const changedFiles = await checkGitDiff();

            // If there are changed files, parse CVE data
            if (changedFiles.length > 0) {
                // logger.info(`Processing changed files: ${changedFiles}`);
                logger.info(`Processing changed files`);
                await parseCVEData(db, changedFiles);  // Pass the changed files
            } else {
                logger.info('No changes detected in Git. Skipping CVE parsing.');
            }

            logger.info('MITRE and Git diff processing completed.');
        } catch (error) {
            logger.error('Error during scheduled job:');
            logger.error( error);
        }

//CVEMAP
        logger.info('Running cvemap script ');
        try {
            await processChangedFilesCvemap('.tmp/input', db);
            // logger.info('Running cvemap script ');
            // await parseCVEMapData(db);
        } catch (error) {
            logger.error(error);
            logger.error('Error during processChangedFileCvemap');
        }

//UNIFIED
        logger.info('running Unified data parsing... ');
        try{
            const db = await connectDB();
            await parseUnifiedData(db);
        } catch (error) {
            logger.error("Error caused during parseUnifiedData");
            logger.error(error);
        }

//SEARCH
      logger.info('updating search collection for autocompelete.');
      try{
        const db = await connectDB();
        await updateSearchCollection(db);
      } catch (error) {
        logger.error("Error caused during updateSearchCollection");
        logger.error(error);
      }
        
//BoxData default
      logger.info('updating BoxData for Home');
      try{
        const db = await connectDB();
        await updateBoxDataStats(db);
      } catch (error) {
        logger.error("Error caused during updateBoxDataStats");
        logger.error(error);
      }

//BoxData vendors
      logger.info('updating BoxData for vendors');
      try{
        const db = await connectDB();
        await updateVendorsBoxDataStats(db);
      } catch (error) {
        logger.error("Error caused during updateVendorsBoxStats");
        logger.error(error);
      }

//BoxData products
      logger.info('updating BoxData for products');
      try{
        const db = await connectDB();
        await updateProductsBoxDataStats(db);
      } catch (error) {
        logger.error("Error caused during updateProductsBoxStats");
        logger.error(error);
      }

//BoxData vendors
      logger.info('updating BoxData for vendors');
      try{
        const db = await connectDB();
        await updateVendorsBoxDataStats(db);
      } catch (error) {
        logger.error("Error caused during updateVendorsBoxDataStats");
        logger.error(error);
      }

// CWE graph
      logger.info('updating Graph Data for Home line graph');
      try{
        const db = await connectDB();
        await updateCWEStats(db);
      } catch (error) {
        logger.error("Error caused during updateCWEStats");
        logger.error(error);
      }

// CVSS graph
      logger.info('updating Graph Data for Home bar graph');
      try{
        const db = await connectDB();
        await updateCvssScoreRanges(db);
      } catch (error) {
        logger.error("Error caused during updateCvssScoreRanges");
        logger.error(error);
      }

// Exploited graph
      logger.info('updating Graph Data for Home radialGraph (exploited)');
      try{
        const db = await connectDB();
        await updateExploitedStats(db);
      } catch (error) {
        logger.error("Error caused during updateExploitedStats");
        logger.error(error);
      }

// Fixes graph
      logger.info('updating Graph Data for Home radialGraph (Fixes)');
      try{
        const db = await connectDB();
        await updateFixesStats(db);
      } catch (error) {
        logger.error("Error caused during updateExploitedStats");
        logger.error(error);
      }

// Top vendors graph
      logger.info('updating Graph Data for Home radialGraph (Top vendors)');
      try{
        const db = await connectDB();
        await updateTopVendorStats(db);
      } catch (error) {
        logger.error("Error caused during updateTopVendorStats");
        logger.error(error);
      }

// CVE Stats graph
      logger.info('updating Graph Data for Home radialGraph ( updated cves )');
      try{
        const db = await connectDB();
        await updateCVEStats(db);
      } catch (error) {
        logger.error("Error caused during updateCVEStats");
        logger.error(error);
      }

// Email for 
      logger.info('Processing Email for Watchlist Users (Alert Email)');
      try{
        const db = await connectDB();
        const users = createUsersModel(db);
        const watchlistCollection = createWatchlistModel(db);
        const watchlistArray = await watchlistCollection.find().toArray();
        for (const watchlistObject of watchlistArray) {

          const watchlist = transfromWatchlist(watchlistObject);

          //email, username, A, M
          const username = watchlist.username;


          const query = { name: watchlist.username };
          const user = await users.findOne(query);

          if (user){
          const email = user.email;
            sendAlertEmail(db, username, email);
          }

        }
        const cves = await db.collection("unified_cves")
          .find({ 'tag': 'R' }, {"_id": 1}).toArray();
        let msg = ` ${cves.length} 'R' tagged cves filtered to send emails`;
        logger.info(msg);
        await db.collection("unified_cves")
          .updateMany({ 'tag': 'R' }, { '$set': { 'tag': 'N' } })
        logger.info("All mail sent and cves tagged 'N' ")

      } catch (e) {
        logger.error("Something broke while sending email (cronJobServices)");
        logger.error(e);
      }
// Dynamic Graphs
      // logger.info('updating Dynamic page Graphs');
      // try{
      //   const db = await connectDB();
      //       
      //   // weakness vendors graph
      //   logger.info('updating CWE collection Home page Graph.');
      //   await updateCWEStats(db);
      //     
      //   // CVSS Home graph
      //   logger.info('updating CVSS collection Home page Graph.');
      //   await updateCVSSStats(db);

      //   // Box data graph
      //   logger.info('updating CVSS collection Home page Graph.');
      //   await updateCVSSHomeStats(db);

      // } catch (error) {
      //   logger.error("Error caused during updateSearchCollection");
      //   logger.error(error);
      // }

    } catch (error) {
      logger.error(error);
      logger.error("Error while running the dataCronJob");
    }

});

//daily 10pm or 22:00
const emailUpdate = cron.schedule(emailUpdateCronString, async () => {
      logger.info('Processing Email for Watchlist Users (emailUpdate Email)');
  try{
    const db = await connectDB();
    const users = createUsersModel(db);
    const watchlistCollection = createWatchlistModel(db);
    const watchlistArray = await watchlistCollection.find().toArray();
    for (const watchlistObject of watchlistArray) {

      const watchlist = transfromWatchlist(watchlistObject);

      //email, username, A, M
      const username = watchlist.username;


      const query = { name: watchlist.username };
      const user = await users.findOne(query);
      if (user) {
        const email = user.email;
        // console.log("email", email);

        sendUpdateEmail(db, username, email);
        msg = `sent Email to ${username}`;
        logger.info(msg);
      }
    }

  } catch (e) {
    logger.error("Something broke while sending email (cronJobServices)");
    logger.error(e);
  }
});

//every Friday 8am 
const emailWeekly = cron.schedule(emailWeeklyCronString, async () => {
      logger.info('Processing Email for Watchlist Users (emailUpdate Weekly)');
  try{
    const db = await connectDB();
    const users = createUsersModel(db);
    const watchlistCollection = createWatchlistModel(db);
    const watchlistArray = await watchlistCollection.find().toArray();
    for (const watchlistObject of watchlistArray) {

      const watchlist = transfromWatchlist(watchlistObject);

      //email, username, A, M
      const username = watchlist.username;


      const query = { name: watchlist.username };
      const user = await users.findOne(query);
      if (user){
        const email = user.email;

        sendWeeklyMonthlyEmail(db, username, email);
        msg = `sent Email to ${username}`;
        logger.info(msg);
      }
    }

  } catch (e) {
    logger.error("Something broke while sending email (cronJobServices)");
    logger.error(e);
  }
});
   
//every Friday 8am 
const emailTodaysActivity = cron.schedule(emailTodaysActivityCronString, async () => {
      logger.info('EMAIL: Processing Email for Watchlist Users ( Todays Activity)');
  try{
    const db = await connectDB();
    const users = createUsersModel(db);
    const watchlistCollection = createWatchlistModel(db);
    const watchlistArray = await watchlistCollection.find().toArray();
    for (const watchlistObject of watchlistArray) {

      const watchlist = transfromWatchlist(watchlistObject);

      //email, username, A, M
      const username = watchlist.username;


      const query = { name: watchlist.username };
      const user = await users.findOne(query);
      if (user){
        const email = user.email;

        sendTodaysActivityEmail(db, username, email);
        msg = `sent Email to ${username}`;
        logger.info(msg);
      }
    }

  } catch (e) {
    logger.error("Something broke while sending email (cronJobServices)");
    logger.error(e);
  }
});
  
//every Friday 8am 
const emailMonthly = cron.schedule(emailMonthlyCronString, async () => {
      logger.info('Processing Email for Watchlist Users (emailUpdate Monthly)');
  try{
    const db = await connectDB();
    const users = createUsersModel(db);
    const watchlistCollection = createWatchlistModel(db);
    const watchlistArray = await watchlistCollection.find().toArray();
    for (const watchlistObject of watchlistArray) {

      const watchlist = transfromWatchlist(watchlistObject);

      //email, username, A, M
      const username = watchlist.username;


      const query = { name: watchlist.username };
      const user = await users.findOne(query);
      if (user) {
        const email = user.email;

        sendMonthlyEmail(db, username, email);
        msg = `sent Email to ${username}`;
        logger.info(msg);
      }
    }

  } catch (e) {
    logger.error("Something broke while sending email (cronJobServices)");
    logger.error(e);
  }
});

cronJob.start();
emailUpdate.start();
emailWeekly.start();
emailMonthly.start();
emailTodaysActivity.start();
nvdCron.start()
