require('dotenv').config(); 
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs")
const saltRounds = 10;
var cookieParser = require('cookie-parser');
var session=require('express-session');

const app = express();
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({extended:true}));
app.use(cookieParser());
app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:false,
    cookie:{maxAge:6000}
    }));

mongoose.connect("mongodb://localhost:27017/RDTDB")

const userSchema = new mongoose.Schema({
    username:{
        type: String,
        // required: true
    },

    email:{
        type: String,
        required : true,
        unique : true
    },

    password:{
        type:String,
        required: true
    },

    role : {
        type:String,
        default : "Manager",
        enum : ["Manager","Admin"]
    }
})


const User = new mongoose.model("User",userSchema);

//Routes

//1.Showing Home page
app.get('/',(req,res)=>{
    res.render("home");
});

//2.Registration
//Showing registration page
app.get('/register',(req,res)=>{
    res.render("register");
});

//Handling signup/registration data
app.post('/register',async (req,res)=>{
    

        const hashedPassword = await bcrypt.hash(req.body.password,saltRounds);
        
        const new_user = new User({
            username: req.body.username,
            email: req.body.email,
            password:hashedPassword
    
        });

        new_user.save((err)=>{
            if(err){
                console.error(err);
                res.redirect('/register')
            }
            else{
                //registration successful 
                req.session.loggedIn=true;
                res.redirect("manager_page");
            }
        });

    });



//3.Login

//a. Manager login
//Showing login page
app.get('/manager_login',(req,res)=>{
    res.render("manager_login");
});

//Handling login 
app.post('/manager_login',(req,res)=>{
   
    const user_email=req.body.email;
    const password=req.body.password;

    User.findOne({email:user_email},async (err,foundUser)=>{
        if(err){
            console.error(err);
            res.redirect('/');
        }
        else{
            if(foundUser){
                //login successful 
                const result =  await bcrypt.compare(password,foundUser.password);
                
                if(result===true){

                    if(foundUser.role==="Manager"){ 
                         req.session.loggedIn=true;
                         res.redirect("/manager_page");
                    }
                    else{
                        console.log("You are not a Manager");
                        res.redirect('/');
                    }
                }

                //incorrect password
                else{
                    console.log("Incorrect password");
                    res.redirect('/manager_login');
                }
        }
        }
    })
});

//manager_page
app.get('/manager_page',(req,res)=>{
    if(req.session.loggedIn) res.render('manager_page');
    else res.redirect('/manager_login');
})

// }
//Admin login

//Showing login page
app.get('/admin_login',(req,res)=>{
    res.render("admin_login");
});

//Handling login 
app.post('/admin_login',(req,res)=>{
   
    const user_email=req.body.email;
    const password=req.body.password;

    User.findOne({email:user_email},async (err,foundUser)=>{
        if(err){
            console.error(err);
            res.redirect('/');
        }
        else{
            if(foundUser){
                //login successful 
                const result =  await bcrypt.compare(password,foundUser.password);
                
                if(result===true){

                    if(foundUser.role==="Admin"){
                         req.session.loggedIn=true;
                         res.redirect("/admin_page");
                    }
                    else{
                        console.log("You are not an Admin");
                        res.redirect('/');
                    }
                }

                //incorrect password
                else{
                    console.log("Incorrect password");
                    res.redirect('/admin_login');
                }
            }
        }
    })

});

//admin_page
app.get('/admin_page',(req,res)=>{
    if(req.session.loggedIn) res.render('admin_page');
    else res.redirect('/admin_login');
})


//logout
app.get('/logout',(req,res)=>{
    req.session.loggedIn=false;
    res.redirect('/');

})
const PORT = process.env.PORT || 3000;

app.listen(PORT,()=>{
    console.log("Server running on port: "+PORT);
});
