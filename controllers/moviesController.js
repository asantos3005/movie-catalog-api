function searchMovies(req, res) {
  const { title, year, page } = req.query;
  const ITEMS_PER_PAGE = 100;
  const currentPage = parseInt(page) || 1;
  const offset = (currentPage - 1) * ITEMS_PER_PAGE;

  // Validate year if provided
  if (year && !/^\d{4}$/.test(year)) {
    return res.status(400).json({
      error: true,
      message: "Invalid year format. Format must be yyyy.",
    });
  }

  // Validate the page number 
  if (page && (!Number.isInteger(Number(page)) || Number(page) < 1)) {
    return res.status(400).json({
      error: true,
      message: "Invalid page format. page must be a number.",
    });
  }



  let baseQuery = req.db.from("basics");

  if (title) {
    baseQuery = baseQuery.where("primaryTitle", "like", `%${title}%`);
  }

  if (year) {
    baseQuery = baseQuery.where("year", year); 
  }

  baseQuery
    .clone()
    .count("* as total")
    .first()
    .then((countResult) => {
      const total = countResult.total;

      return baseQuery
        .clone()
        .select(
          "primaryTitle as title",
          "year",
          "tconst as imdbID",
          "imdbRating",
          "rottenTomatoesRating",
          "metacriticRating",
          "rated as classification"
        )
        .limit(ITEMS_PER_PAGE)
        .offset(offset)
        .then((rows) => {
          // Convert rating fields to numbers
          const formattedRows = rows.map((movie) => ({
            ...movie,
            imdbRating: movie.imdbRating !== null ? Number(movie.imdbRating) : null,
            rottenTomatoesRating: movie.rottenTomatoesRating !== null ? Number(movie.rottenTomatoesRating) : null,
            metacriticRating: movie.metacriticRating !== null ? Number(movie.metacriticRating) : null,
          }));

          res.status(200).json({
            data: formattedRows,
            pagination: {
              total: total,
              lastPage: Math.ceil(total / ITEMS_PER_PAGE),
              perPage: ITEMS_PER_PAGE,
              currentPage: currentPage,
              from: offset,
              to: offset + rows.length,
              prevPage: currentPage > 1 ? currentPage - 1 : null,
              nextPage: currentPage < Math.ceil(total / ITEMS_PER_PAGE) ? currentPage + 1 : null,
            },
          });
        });
    })
    .catch((err) => {
      console.error(err);
      res.status(500).json({
        Error: true,
        Message: "Error executing MySQL query",
      });
    });
}





async function getMovieData(req, res) {
  const imdbID = req.params.imdbID;

  // Reject any unexpected query params
  const queryParams = Object.keys(req.query);
  if (queryParams.length > 0) {
    return res.status(400).json({
      error: true,
      message: `Invalid query parameters: ${queryParams.join(", ")}. Query parameters are not permitted.`,
    });
  }

  // Check basic format
  if (!imdbID || typeof imdbID !== 'string') {
    return res.status(400).json({
      error: true,
      message: "Invalid imdbID format.",
    });
  }

  try {
    // Get basic movie info
    const movie = await req.db("basics")
      .select(
        "primaryTitle as title",
        "year",
        "runtimeMinutes as runtime",
        "genres",
        "country",
        "boxoffice",
        "poster",
        "plot"
      )
      .where("tconst", imdbID)
      .first();

    if (!movie) {
      return res.status(404).json({
        error: true,
        message: "Movie not found",
      });
    }

    // Convert genre string to array
    movie.genres = movie.genres ? movie.genres.split(",") : [];

    // Get principals in separate table
    const principals = await req.db("principals")
      .join("names", "principals.nconst", "names.nconst")
      .select(
        "principals.nconst as id",
        "principals.category",
        "names.primaryName as name",
        "principals.characters"
      )
      .where("principals.tconst", imdbID);

    movie.principals = principals.map((person) => ({
      id: person.id,
      category: person.category,
      name: person.name,
      characters: person.characters ? JSON.parse(person.characters) : [],
    }));

    // Get all available ratings for the movie
    const ratings = await req.db("ratings")
      .select("source", "value")
      .where("tconst", imdbID);

    movie.ratings = ratings.map((r) => ({
      source: r.source,
      value: parseFloat(r.value),
    }));

    res.status(200).json(movie);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      message: "Server error",
    });
  }
}



module.exports = { searchMovies, getMovieData }

