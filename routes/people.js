const express = require('express');
const router = express.Router();
const peopleController = require('../controllers/peopleController');

router.get('/:imdbID', peopleController.getPersonData);


module.exports = router;
