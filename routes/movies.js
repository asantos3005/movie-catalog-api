const express = require('express');
const router = express.Router();
const moviesController = require('../controllers/moviesController');

router.get('/search', moviesController.searchMovies);
router.get('/data/:imdbID', moviesController.getMovieData);


module.exports = router;
