const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const cookieParser = require("cookie-parser");
const Blog = require("./models/blog");
const userRoute = require("./router/user");
const blogRoute = require("./router/blog");
const { checkForAuthenticationCookie } = require("./middlewares/authentications")

const app = express();
const PORT = process.env.PORT || 8000;

mongoose.connect("mongodb://127.0.0.1:27017/blogify").
    then(e => {
        console.log("MongoDB connnected");
    })


app.set("view engine", "ejs");
app.set("views", path.resolve("./views"));

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(checkForAuthenticationCookie("token"));
app.use(express.static(path.resolve("./public")));

app.get("/", async (req, res) => {
    const allBlog = await Blog.find({});
    return res.render("homepage", {
        user: req.user,
        blogs: allBlog,
    });
})

app.use("/user", userRoute);
app.use("/blog", blogRoute);

app.listen(PORT, () => {
    console.log(`Server listening on port : ${PORT}`);
})