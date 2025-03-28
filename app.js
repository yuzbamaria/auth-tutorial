const express = require("express");
const db = require("./connection");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());

// create a token for the user 
// respond to the user with the token 
app.post("/signup", async (req, res, next) => {
    // retrieve the user's credentials from the req obj 
    const { username, password } = req.body;
    // console.log(username, password);
    // hash out the password 
    const hash = await bcrypt.hash(password, 10);
    // console.log(hash);

    // store the credentials in the db
    try {
        await db.query(
            "INSERT INTO users (username, password_hash) VALUES ($1,$2)", [
                username, 
                hash
            ]);
        const { TOKEN_SECRET } = process.env;
        // console.log(TOKEN_SECRET)
        const token = jwt.sign({ user: username, iat: Date.now() }, TOKEN_SECRET);
        console.log(token);
        res.status(201).send({ token })
    } catch(err) {
        res.status(400).send({ msg: "User already exists."});
    }
});

// retrieve username and password 
// attempt to retrieve the user from the db 
// check it's correct password 
// provide them with a token 

app.post("/signin", async (req, res, next) => {
    const { username, password } = req.body;
    const { rows: users } = await db.query(
        `SELECT * FROM users WHERE username = $1`, [username]
    );
    const hash = users[0].password_hash;
    // console.log(hash)
    const passwordsMatch = await bcrypt.compare(password, hash);
    if (passwordsMatch) {
        // generate a token 
        const { TOKEN_SECRET } = process.env;
        // console.log(TOKEN_SECRET)
        const token = jwt.sign({ user: username, iat: Date.now() }, TOKEN_SECRET);
        console.log(token);
        res.status(201).send({ token })
    } else {
        res.status(401).send({ msg: "incorrect credentials" })
    }
});

// middleware to block users accesing get "/api"
app.use((req, res, next) => {
    const { authorization } = req.headers;
    console.log("Authorization token", authorization);

    // check if this is a valid jwt token for this endpoint:
    // if there's no token, let the user know
    if(!authorization) {
        res.status(401).send({msg: "invalid authorization"});
    };

    //  if the user do have a token, isolate the token from the Bearer
    const token = authorization.split(" ")[1];
    const { TOKEN_SECRET } = process.env;

    console.log("Token:", token)
    console.log("Token secret:", TOKEN_SECRET)

    try {
        jwt.verify(token, TOKEN_SECRET);
        next();
    } catch(err) {
        res.status(401).send({msg: "invalid authorization token"});
    };
});

app.get("/api", (req, res, next) => {
    res.send({ msg: "hello" });
});

app.listen(9070, () => console.log("App listening on port 9070!"));