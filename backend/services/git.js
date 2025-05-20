const simpleGit = require("simple-git");
const fs = require("fs");
const path = require("path");
const logger = require("../logger");

const repoPath = path.resolve(__dirname, process.env.ASSETS, "../cvelistV5"); // Path to your local repository
const git = simpleGit(repoPath);

async function cloneOrPullRepo() {
  try {
    const isRepo = await git.checkIsRepo();

    if (!isRepo) {
      logger.info("Cloning repository...");
      await git.clone("https://github.com/CVEProject/cvelistV5.git", repoPath);
    } else {
      logger.info("Pulling the latest changes...");
      await git.pull();
    }
  } catch (error) {
    if (error.message.includes("cannot lock ref")) {
      logger.error("Git lock error detected, attempting to resolve...");
      try {
        // Attempt to remove the lock file
        const lockFile = path.join(
          repoPath,
          ".git/refs/remotes/origin/main.lock",
        );
        if (fs.existsSync(lockFile)) {
          fs.unlinkSync(lockFile);
          logger.info("Removed stale lock file. Retrying pull...");
          await git.pull();
        } else {
          throw new Error(
            "Lock file not found, manual intervention may be needed.",
          );
        }
      } catch (lockError) {
        logger.error("Failed to remove lock file:");
        logger.error(lockError);
      }
    } else {
      logger.error("Error pulling/cloning repository:");
      logger.error(error);
    }
  }
}

module.exports = { cloneOrPullRepo };
