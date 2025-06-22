const cors = require('cors');
const swaggerUI = require('swagger-ui-express');
const swaggerDocument = require('./docs/openapi.json');
const https = require('https');
const fs = require('fs');
const express = require('express');
const knex = require('knex');
const moviesRoutes = require('./routes/movies');
const peopleRoutes = require('./routes/people');
const userRoutes = require('./routes/user');
const options = require('./knexfile');
require('dotenv').config();


const app = express();
const db = knex(options);

app.use('/', cors({ origin: '*' }), swaggerUI.serve);
app.get('/', cors({ origin: '*' }), swaggerUI.setup(swaggerDocument));

app.use(cors());
app.use(express.json());

const credentials = {
  key: fs.readFileSync('selfsigned.key', 'utf8'),
  cert: fs.readFileSync('selfsigned.crt', 'utf8'),
};

// Attach the db instance to every request
app.use((req, res, next) => {
  req.db = db;
  next();
});

// Mount routes
app.use('/movies', moviesRoutes);
app.use('/people', peopleRoutes);
app.use('/user', userRoutes);


// Test route for knex connection
/*
app.get('/knex', (req, res, next) => {
  req.db
    .raw('SELECT VERSION()')
    .then((version) => {
      console.log(version[0][0]);
      res.send('Database version logged successfully poop');
    })
    .catch((err) => {
      console.error(err);
      res.status(500).send('Error testing database connection');
    });
});
*/

// Deployment for Uni Assignment
/* 
const server = https.createServer(credentials, app);
server.listen(3000, () => {
  console.log('HTTPS Server running on https://localhost:3000');
});
*/

// Deployment for Render

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});