const { createHmac, randomBytes } = require("crypto");
const { Schema, model } = require("mongoose");
const { createTokenForUser } = require("../services/auth")

const userSchema = new Schema({
    fullName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    salt: {
        type: String,
    },
    password: {
        type: String,
        required: true,
    },
    profilePhoto: {
        type: String,
        default: "../public/images/profile.jpeg"
    },
    role: {
        type: String,
        enum: ["user", "admin"],
        default: "user",
    }
}, { timestamps: true });

userSchema.pre("save", async function (next) {
    const user = await this;
    if (!user.isModified("password")) return;

    const salt = randomBytes(16).toString();
    // const salt = "someRandomSalt";
    const hashedPassword = createHmac("sha256", salt).update(user.password).digest("hex");

    this.salt = salt;
    this.password = hashedPassword;

    next();
})

userSchema.static("matchPasswordAndGenerateToken", async function (email, password) {
    const user = await this.findOne({ email: email });
    // console.log("email:", email);
    if (!user) throw new Error("User not found");

    const salt = user.salt;
    const hashedPassword = user.password;
    const userProvidedHash = createHmac("sha256", salt).update(password).digest("hex");

    if (userProvidedHash !== hashedPassword) throw new Error("Wrong password");
    const token = createTokenForUser(user);
    return token;
})

const Users = model("user", userSchema);

module.exports = Users;