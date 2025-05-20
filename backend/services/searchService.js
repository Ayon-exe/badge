const { createUnifiedModel } = require("../models/CVE");
const logger = require("../logger");

const updateSearchCollection = async (db) => {
  const unifiedCollection = createUnifiedModel(db);

  // Fetch all distinct vendor and product names
  const results = await unifiedCollection.aggregate([
    {
      $unwind: '$cpe'
    },
    {
      $group: {
        _id: null,
        vendors: { $addToSet: '$cpe.vendor' },
        cve_ids: { $addToSet: '$cve_id' },
        products: { $addToSet: '$cpe.product' }
      }
    },
    {
      $project: {
        _id: 0,
        vendors: 1,
        cve_ids: 1,
        products: 1
      }
    }
  ]).toArray();

  if (results.length > 0) {
    const { vendors, cve_ids, products } = results[0];

    // Clean product names and ensuring only unique names
    const cleanedProductsSet = new Set();
    products.forEach(product => {
      const cleanedProduct = product.replace(/\s*prior to.*$/i, "").trim();
      cleanedProductsSet.add(cleanedProduct);
    });
    const cleanedProducts = Array.from(cleanedProductsSet);

    // Upsert the search collection with the new vendor and product data
    await db.collection('search').updateOne(
      { _id: 'search_data' },
      { $set: { vendors, cve_ids, products, cleaned_products: cleanedProducts } },
      { upsert: true }
    );

    logger.info('Search collection updated successfully with unique cleaned products, keeping Google Chrome and Google Chrome OS distinct.');
  } else {
    logger.info('No vendor or product data found.');
  }
};

module.exports = {
  updateSearchCollection
};
