const { verifyAccessToken } = require("../utils/jwtUtils");

const getPersonData = async (req, res) => {
  // Reject other params - should just be the one
  if (Object.keys(req.query).length > 0) {
    return res.status(400).json({
      error: true,
      message: "Invalid query parameters: " + Object.keys(req.query).join(', ') + ". Query parameters are not permitted.",
    });
  }

  // auth in header not body - through Authrization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: true,
      message: "Authorization header ('Bearer token') not found",
    });
  }

  //Validate token
  const token = authHeader.split(' ')[1];
  try {
    verifyAccessToken(token); // Throws if invalid or expired
  } catch (err) {
    return res.status(401).json({
      error: true,
      message: "Invalid JWT token",
    });
  }

  const nconst = req.params.imdbID;

  try {
    // 4. Get person from names table
    const person = await req.db('names')
      .select('primaryName', 'birthYear', 'deathYear')
      .where({ nconst })
      .first();

    if (!person) {
      return res.status(404).json({
        error: true,
        message: "No record exists of a person with this ID",
      });
    }

    // 5. Get roles from principals table
    const roles = await req.db('principals')
      .select('tconst', 'category', 'characters')
      .where({ nconst });

    // 6. Get movie info for each role
    const detailedRoles = await Promise.all(
      roles.map(async (role) => {
        const movie = await req.db('basics')
          .select('primaryTitle', 'imdbRating')
          .where({ tconst: role.tconst })
          .first();

        return {
          movieName: movie?.primaryTitle || 'Unknown',
          movieId: role.tconst,
          category: role.category,
          characters: role.characters ? JSON.parse(role.characters) : [],
          imdbRating: movie?.imdbRating ? parseFloat(movie.imdbRating) : null,
        };
      })
    );

    // 7. Respond
    return res.status(200).json({
      name: person.primaryName,
      birthYear: person.birthYear,
      deathYear: person.deathYear,
      roles: detailedRoles,
    });

  } catch (err) {
    console.error("Error retrieving person:", err);
    return res.status(500).json({
      error: true,
      message: "Internal server error.",
    });
  }
};

module.exports = { getPersonData };
