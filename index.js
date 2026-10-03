import express from "express";
import pg from "pg";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import session from "express-session";

dotenv.config();

const { Pool } = pg;

const db = new Pool({
    connectionString: process.env.DATABASE_URL
});

db.query("SELECT NOW()", (err, result) => {
    if (err) {
        console.log("Database connection error");
    } else {
        console.log("Database connected");
    }
});

const app = express();

app.use(session({
    secret: "my-blog-secret",
    resave: false,
    saveUninitialized: false
}));

const port = 3000;

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));


// Home

app.get("/", (req, res) => {

    res.render("home", {
        firstName: req.session.firstName || null,
        userId: req.session.userId || null
    });

});


// Raags

app.get("/raags", async (req, res) => {

    try {

        const result = await db.query(
            "SELECT id, name, thaat, introduction FROM raags ORDER BY id"
        );

        res.render("raags", {
            raags: result.rows,
            userId: req.session.userId || null
        });

    } catch (error) {

        console.log(error);
        res.send("Something went wrong.");

    }

});


// Individual Raag

app.get("/raags/:id", async (req, res) => {

    if (!req.session.userId) {
        return res.redirect("/login");
    }

    try {

        const result = await db.query(
            "SELECT * FROM raags WHERE id = $1",
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.send("Raag not found.");
        }

        res.render("raag", {
            raag: result.rows[0],
            userId: req.session.userId
        });

    } catch (error) {

        console.log(error);
        res.send("Something went wrong.");

    }

});


// Learn

app.get("/learn", (req, res) => {

    res.render("learn", {
        userId: req.session.userId || null
    });

});


// Signup

app.get("/signup", (req, res) => {
    res.render("signup", {
        firstNameError: "",
        lastNameError: "",
        emailError: "",
        phoneError: "",
        passwordError: "",
        userId: req.session.userId || null
    });
});


app.post("/signup", async (req, res) => {

    const firstName = req.body.firstName;
    const lastName = req.body.lastName;
    const email = req.body.email;
    const phone = req.body.phone;
    const password = req.body.password;


    if (!email || !phone || !password || !firstName || !lastName) {

        return res.render("signup", {
            firstNameError: "All fields are required"
        });

    }


    if (!/^[A-Za-z]+$/.test(firstName)) {

        return res.render("signup", {
            firstNameError: "Only letters are allowed"
        });

    }


    if (!/^[A-Za-z]+$/.test(lastName)) {

        return res.render("signup", {
            lastNameError: "Only letters are allowed"
        });

    }


    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {

        return res.render("signup", {
            emailError: "Please enter a valid email"
        });

    }


    if (!/^[0-9]{10}$/.test(phone)) {

        return res.render("signup", {
            phoneError: "Phone number must be exactly 10 digits"
        });

    }


    if (password.length < 8) {

        return res.render("signup", {
            passwordError: "Password must be at least 8 characters"
        });

    }


    const hashedPassword = await bcrypt.hash(password, 10);


    try {

        const result = await db.query(
            "INSERT INTO users (first_name, last_name, email, phone, password) VALUES ($1, $2, $3, $4, $5) RETURNING id, first_name, last_name",
            [firstName, lastName, email, phone, hashedPassword]
        );


        req.session.userId = result.rows[0].id;
        req.session.firstName = result.rows[0].first_name;

        res.redirect("/");

    } catch (error) {

        if (error.code === "23505") {

            if (error.constraint === "users_email_key") {

                return res.render("signup", {
                    emailError: "Email is already registered"
                });

            }


            if (error.constraint === "users_phone_key") {

                return res.render("signup", {
                    phoneError: "Phone number is already registered"
                });

            }

        }


        console.log(error);

        return res.render("signup", {
            emailError: "Something went wrong. Please try again."
        });

    }

});


// Login

app.get("/login", (req, res) => {

    res.render("login", {
            emailError: "",
            error: "",
            userId: req.session.userId || null
    });

});


app.post("/login", async (req, res) => {

    const email = req.body.email;
    const password = req.body.password;


    if (!email || !password) {

        return res.render("login", {
            error: "Email and password are required"
        });

    }


    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {

        return res.render("login", {
            error: "Please enter a valid email address"
        });

    }


    try {

        const result = await db.query(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );


        if (result.rows.length === 0) {

            return res.render("login", {
                error: "Email is not registered"
            });

        }


        const isPasswordCorrect = await bcrypt.compare(
            password,
            result.rows[0].password
        );


        if (!isPasswordCorrect) {

            return res.render("login", {
                error: "Incorrect password"
            });

        }


        req.session.userId = result.rows[0].id;
        req.session.firstName = result.rows[0].first_name;

        res.redirect("/");

    } catch (error) {

        console.log(error);

        res.render("login", {
            error: "Something went wrong. Please try again."
        });

    }

});


// Logout

app.get("/logout", (req, res) => {

    req.session.destroy(() => {

        res.redirect("/");

    });

});


app.listen(port, () => {

    console.log(`Server is running on http://localhost:${port}`);

});