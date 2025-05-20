const logger = require("../logger");
const simpleGit = require("simple-git");
const fs = require("fs");
const path = require("path");
require("dotenv").config(); // Load .env variables

const git = simpleGit(path.join(__dirname, process.env.ASSETS, "../cvelistV5")); // Adjust the path to your repo directory

async function checkGitDiff() {
  try {
    // Fetch the latest changes from the remote repository
    await git.fetch();

    // Check if the local branch is behind the remote
    const status = await git.status();
    if (status.behind > 0) {
      logger.info(
        `Your branch is ${status.behind} commit(s) behind the remote. Pulling latest changes...`,
      );

      const pullResult = await git.pull();
      logger.info("Pulling the latest changes...");
      logger.info("Files updated in pull:"); // Log which files were updated
      logger.info(pullResult.files); // Log which files were updated
    } else {
      logger.info("Your branch is up to date with the remote.");
    }

    // Now check for git diff against the last commit
    const changedFiles = await git.diffSummary(["HEAD@{1}"]); // Compare with the last commit

    if (changedFiles.files.length === 0) {
      logger.info("No changes detected in git diff after the pull.");
    } else {
      const dirPath = path.join(process.cwd(), ".tmp");

      if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
        logger.info("Directory created:");
        logger.info(dirPath);
      } else {
        logger.info(`Directory already exists: ${dirPath}`);
      }

      const changedFilesList = changedFiles.files
        .map((file) => file.file)
        .join("\n");

      // Write to a file named "changes"
      fs.writeFile(".tmp/changes", changedFilesList, (err) => {
        if (err) {
          logger.error("Error writing to file");
          logger.error(err);
        } else {
          logger.info("Changed files have been written to changes");
        }
      });
      logger.info("Changed files after the pull:"); // Log the changed files
      logger.info(changedFiles.files.map((file) => file.file)); // Log the changed files
    }

    return changedFiles.files.map((file) => file.file);
  } catch (error) {
    logger.error("Error checking git diff:");
    logger.error(error);
    throw error; // Rethrow the error to handle it in the calling function
  }
}

module.exports = {
  checkGitDiff,
};
