// const { updateSearchCollection } = require("./services/searchService");
const { parseUnifiedData  } = require("./services/unified");
// const { checkGitDiff } = require("./services/gitdiff"); // Import checkGitDiff
// const { cloneOrUpdateMITRERepo, parseCVEData } = require('./services/mitreService');
// const { parseCVEMapData, processChangedFilesCvemap } = require("./services/cvemapService");
const connectDB = require("./config/db");
const { 
  updateBoxDataStats, 
  updateVendorsBoxDataStats,
  updateProductsBoxDataStats,
  updateCWEStats,
  updateCvssScoreRanges,
  updateExploitedStats,
  updateFixesStats,
  updateTopVendorStats,
  updateCVEStats,
  processTopProductByFixes,
  getProductVersions,
  getTopProductByFixes,
} = require("./controllers/cveController");

const {
  addProductToWatchlist,
  removeProductFromWatchlist,
} = require("./controllers/watchlistController");
const { 
  sendAlertEmail, 
  sendWeeklyMonthlyEmail, 
  sendUpdateEmail,
  sendTodaysActivityEmail,
  sendAction, 
  parseUpdates, 
  generateCsvData, 
  extractVendorWithMetadata 
} = require("./services/watchlistService");

const {
  getTotalCVEs,
  getPatchableCVEs,
  getHighRiskCVEs,
  getNewCVEs,
  getWeeklyMonthlyData,
  getUpdateData,
  getTodaysActivityData,
} = require("./controllers/emailController");

  const {
    getAlertEmail
} = require("./emailTemplates/AlertEmail");

const main = async ()=> {
    try{
        const db = await connectDB();
      // Listen for data events
        // console.log( 'getTotalCVEs(db, "vik")');
        // console.log( await getTotalCVEs(db, "vik") );
        // console.log( 'getPatchableCVEs(db, "vik")');
        // console.log( await getPatchableCVEs(db, "vik"));
        // console.log( 'getHighRiskCVEs(db, "vik")');
        // console.log( await getHighRiskCVEs(db, "vik"));
        console.log( 'getNewCVEs(db, "vik")');
        console.log( await getNewCVEs(db, "vik"));
        // console.log( 'getWeeklyMonthlyData(db, "vik")');
        // console.log( await getWeeklyMonthlyData(db, "vik"));
        // console.log( 'getUpdateData(db, "vik")');
        // console.log( await getUpdateData(db, "vik"));
        // console.log( 'getTodaysActivityData(db, "vik")');
        // console.log( await getTodaysActivityData(db, "vik"));
      // console.log( await processTopProductByFixes(db));
      // console.log( await getProductVersions(db, 'IBM'));
        // await updateSearchCollection(db);
        // await updateCVSSHomeStats(db);
        // console.log( await getTotalCVEs(db, "vik") );
        // console.log( await getPatchableCVEs(db, "vik") );
        // console.log( await getHighRiskCVEs(db, "vik") );
        // await updateCVSSHomeStats(db);
      // await updateBoxDataStats(db);
      // await updateProductsBoxDataStats(db);
      // console.log(await getTopProductByFixes(db));
      // await updateVendorsBoxDataStats(db);
      // await updateCWEStats(db);
      // await updateCvssScoreRanges(db);
      // await updateExploitedStats(db);
      // await updateFixesStats(db);
      // await updateTopVendorStats(db);
      // await updateCVEStats(db);
        //     const changedFiles = await checkGitDiff();

        //     // If there are changed files, parse CVE data
        //     if (changedFiles.length > 0) {
        //         // logger.info(`Processing changed files: ${changedFiles}`);
        //         logger.info(`Processing changed files`);
        //         await parseCVEData(db, changedFiles);  // Pass the changed files
        //     } else {
        //         logger.info('No changes detected in Git. Skipping CVE parsing.');
        //     }
        //     await processChangedFilesCvemap('.tmp/input', db);
        //     logger.info('cvemap script ');
        //     await parseNVDData(db);
        //     logger.info('NVD data parsing completed successfully.');
        // await parseUnifiedData(db);
// console.log( typeof(getAlertEmail) );

      // const username = "vik";
      // const email = "vigoxab696@oronny.com";
      await sendAlertEmail( db,'vik' , "wopiray978@movfull.com") ;
      //await sendWeeklyMonthlyEmail( null, username, email); 
      //await sendUpdateEmail( null, username, email); 
       await sendTodaysActivityEmail( db, "vik", "wopiray978@movfull.com"); 
  ///await sendAction(db, username, email); 
      // await parseUpdates(db);


      // await generateCsvData(".tmp/updat.csv");
      // const updates = await extractVendorWithMetadata(db,".tmp/updat.csv");
      // await parseUpdates(db, updates);
      // console.log("testing 4321");

      // const username = 'vik';
      // const watchlistName = 'foobar';
      // const version = '11.121.34.55';
      // const productName = 'Lindell17';

      // console.log( await addProductToWatchlist(db, username, watchlistName, productName, version));
      // console.log( await removePrgjvoductFromWatchlist(db, username, watchlistName, productName));

    } catch (error) {
        console.error(error);
    } finally {
        console.log("Task Done");
    }
}

main();


