import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv"

const saltRounds=10;
const app = express();
const port = 3000;
env.config();

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "divyam@post",
  port: 5432,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret:process.env.SESSION_SECRET,
  resave:false,
  saveUninitialized:true,
  cookie:{
    maxAge:1000*60*60*24,
  }
})
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});
app.get("/secrets",(req,res)=>{
   if(req.isAuthenticated())
    {
      res.render("secrets.ejs");
    }
    else
    {
      res.redirect("login");
    }
});
app.post("/register", async (req, res) => {
  const email=req.body.username;
  const password=req.body.password;

  try{
  const check=await db.query("SELECT * FROM users WHERE email=$1",[email]);
  if(check.rows.length>0){
    res.send("user already exsists");
  }
  else{
    bcrypt.hash(password,saltRounds,async(err,hash)=>{
      if(err)
      {
        console.log(err);
      }
      else{
      const result = await db.query("INSERT INTO users (email,password) VALUES ($1,$2) RETURNING *",[email,hash]);
      const user=result.rows[0];
      req.login(user,(err)=>{
        console.log(err);
        res.redirect("/secrets")
      })
      }
    })
  
  }
}
catch(err)
{
  console.log(err);
}
});

app.post("/login", passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login"
}));
passport.use(new Strategy(async function verify(username,password,cb){
  console.log(username);
  try{
    const result =await db.query("SELECT * FROM users WHERE email= $1",[username]);
    console
    if(result.rows.length>0)
      {
        const user=result.rows[0];
        const storedPass=user.password;
        bcrypt.compare(password,storedPass,(err,result)=>{
          if(err)
            return cb(err);
          else
             if(result)
              {
                 return cb(null,user);
              }
              else
              {
                return cb(null,false);
              }
        })
      }
      else
      {
        return cb("user has not registered");
      }
    }
    catch(err)
    {
      return cb(err);
    }
}))
passport.serializeUser((user,cb)=>{
  cb(null,user);
})
passport.deserializeUser((user,cb)=>{
  cb(null,user);
})
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
