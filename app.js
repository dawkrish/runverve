/* standard libaries */
const path = require("path") // library to get path of database.json
const fs = require("fs") // library for reading and writing files

/* installed libaries */
require("dotenv").config()
const brcypt = require("bcrypt") // library for hashing password
const jwt = require("jsonwebtoken") // library for creating jwt tokens for authorization
const cookieParser = require("cookie-parser") // library to parse cookies from request
const express = require('express') // library for creating express server
const app = express()

/* constants */
const PORT = 8080 // PORT number
const DB_FILE_PATH = path.join(__dirname, ".", "database.json") // local database.json to store users

/* middleware */
app.use(cookieParser())
app.use(express.json())

/* use to make json response look good */ 
app.set('json spaces', 5);

/* util function #1 - READ FROM DATABASE */
function readDB() {
    /* 
    - read database.json
    - parse it 
    */ 
    const data = fs.readFileSync(DB_FILE_PATH, "utf8")
    return JSON.parse(data)
}
/* util function #2 - WRITE USER DATABASE */
async function writeUser(name, email, plainPassword) {
    /* 
    - hash the plain password
    - create user object
    - fetch existing users (array)
    - create new users (array)
    - write back to database.json
    */ 
    try {
        const hashedPassword = await brcypt.hash(plainPassword, 10) 
        const user = {
            "name": name,
            "email": email,
            "password": hashedPassword
        }
        const db = readDB()
        const existingUsers = db.users
        const newUsers = [...existingUsers, user]
        db.users = newUsers
        fs.writeFile(DB_FILE_PATH, JSON.stringify(db), (err) => {
            if (err) {
                throw new Error("error has occured writing file : ", err)
            }
            console.log('Data written successfully to disk');
        })
    }
    catch (e) { console.log(e); return }
}

/* util function #3 - VERIFY JWT TOKEN */
function verifyJWT(token){
    /*
    - verify jwt
    - if there is no error catch, return null (error)
    - else, return error message
    */ 
    try{
        const resp = jwt.verify(token,process.env.JWT_SECRET)
        return null
    }catch(e){
        return e.message
    }
}

/* 
GET / 
Home 
*/
app.get("/",(req,res)=>{
    res.send("this is home page, access to everyone")
})

/* 
GET / 
Protected 
*/
app.get("/protected", (req, res) => {
    /*
    - fetch token from request.cookies
    - fetch error via "verifyJWT(<args>)"
    - if no error, you are logged in
    - else we need to re-login
    */ 
    const token = req.cookies.token
    const err = verifyJWT(token)
    if (err == null) {
        res.send("you are authorized, you are able to access the protected page")
        return
    }
    res.json({"error" : err,"message" : "re-login"})
})

/* 
GET /user 
Fetch All Users 
*/
app.get("/user", (req, res) => {
    /*
    - fetch users
    - make new users which does not include password fields
    */ 
    const db = readDB()
    const users = db.users

    const newUsers = []
    for (let i = 0; i < users.length; i++) {
        const user = {
            "name": users[i].name,
            "email": users[i].email
        }
        newUsers.push(user)
    }
    res.json(newUsers)
})

/* 
POST / 
Signup
*/
app.post("/signup", (req, res) => {
    /*
    - check for name,email,password fields empty or not (this can be done on client side, but an extra security)
    - fetch users
    - check for existing name, existing email
    - write user via "writeUser(<args>)"
    */ 
    try {
        const requestBody = req.body

        if (requestBody.name === "") { throw new Error("name field empty") }
        if (requestBody.email === "") { throw new Error("email field is empty") }
        if (requestBody.password === "") { throw new Error("password field is empty") }


        const db = readDB()
        const users = db.users;

        for (let i = 0; i < users.length; i++) {
            if (users[i].name === requestBody.name) {
                throw new Error("this name already exists");
            }
            if (users[i].email === requestBody.email) {
                throw new Error("this email already exists");
            }
        }

        writeUser(req.body.name, req.body.email, req.body.password)
        userToReturn = {
            "name": req.body.name,
            "email": req.body.email
        }
        res.json(userToReturn)
    } catch (e) {
        res.json({ "error": e.message })
    }
})

/* 
POST / 
Login
*/
app.post("/login", async(req, res) => {
    /*
    - check for name,password fields empty or not (this can be done on client side, but an extra security)
    - check if this name exists in database or not
    - check if the password associated with that name is correct or not
    - sign jwt token
    - set token in response cookies
    */
    const requestBody = req.body
    try {
        if (requestBody.name === "") { throw new Error("name field empty") }
        if (requestBody.password === "") { throw new Error("password field is empty") }

        const db = readDB()
        const users = db.users
        
        let isNameThere = false
        let isPassword = null
        for(let i = 0; i < users.length; i++){
            if(users[i].name === requestBody.name){
                isNameThere = true
                isPassword = users[i].password
                break
            }
        }
        if(isNameThere == false){throw new Error("name does not exist")}
        const result = await brcypt.compare(requestBody.password, isPassword)

        if (result == false){throw new Error("password does not match")}

        const token = jwt.sign({"name" : requestBody.name},process.env.JWT_SECRET,{expiresIn : 20})
        res.cookie("token",token)
        res.json({"token" : token})
    } catch (e) {
        res.json({ "error": e.message })
    }
})

/* server listening on port */
app.listen(PORT, () => {
    console.log(`server listening on  http://localhost:${PORT}`)
})