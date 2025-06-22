module.exports = {
  client: 'mysql2',
  connection: {
    host: 'mysql-movie-db-filmary-movies-db-filmary.b.aivencloud.com', // from Aiven
    port: 12392, // from Aiven
    database: 'movies', 
    user: 'avnadmin', // from Aiven
    password: 'AVNS_Ggi5nCMypEVtKSABm2_' // replace with the actual password
  }
};