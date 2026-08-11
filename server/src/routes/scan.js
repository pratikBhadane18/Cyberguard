const express = require('express');
const router = express.Router();
const scanController   = require('../controllers/scanController');
const reportController = require('../controllers/reportController');

router.post('/scan',   scanController.scan);
router.post('/report', reportController.generateReport);

module.exports = router;
