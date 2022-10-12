const router = require("express").Router();

const User = require("../models/User.model.js");

const bcrypt = require("bcryptjs"); 
const saltRounds = 10; 

const isLoggedIn = require("../middleware/isLoggedIn.js");
const isLoggedOut = require("../middleware/isLoggedOut.js");


router.get("/signup",isLoggedOut, (req, res, next)=>{
    const data = {};
    if(req.session.currentUser) data.username = req.session.currentUser.username;
    res.render("users/signup", data);
})

router.post("/signup", isLoggedOut, (req, res, next)=>{
    const {username, password, passwordRepeat} = req.body;

    if(!username || !password  || !passwordRepeat) {
        const data = {mensajeError: "Faltan campos por rellenar"};
        if(req.session.currentUser) data.username = req.session.currentUser.username;
        res.render("users/signup", data);
        return;
    }
    if(password != passwordRepeat) {
        const data = {mensajeError: "Passwords diferentes"};
        
        res.render("users/signup", data);
        return;
    }

    const salt = bcrypt.genSaltSync(saltRounds);
    const passwordHash = bcrypt.hashSync(password, salt);

    User.create({
        username,
        password: passwordHash
    })
    .then(result => {
        req.session.currentUser=result; 
        res.redirect("/users/profile");    
    })
    .catch(err => {
        const data = {mensajeError: err};
        if(req.session.currentUser) data.username = req.session.currentUser.username;
        res.render("error", data)  
    })
})

router.get("/login", isLoggedOut, (req, res, next)=>{
    res.render("users/login");
})

router.post("/login", isLoggedOut, (req, res, next)=>{

    const { username, password } = req.body;

    User.findOne({username})
    .then(user => { 

        if(bcrypt.compareSync(password, user.password)) {
            req.session.currentUser=user;   
            res.redirect("/users/profile");
        } else {
            const data = {mensajeError: "credenciales incorrectas"};
            if(req.session.currentUser) data.username = req.session.currentUser.username;

            res.render("users/login", data)
        }

    })
    .catch(err => {
        res.render("error", {mensajeError: err})   
    })
})

router.get("/profile", isLoggedIn ,(req, res, next)=>{
    const data = {mensajeError: "No estás loggeado"};
    if(req.session.currentUser) data.username = req.session.currentUser.username;

    res.render("users/profile", data);    
});

router.get("/main", isLoggedIn ,(req, res, next)=>{
    const data = {mensajeError: "No estás loggeado"};
    if(req.session.currentUser) data.username = req.session.currentUser.username;

    res.render("users/main", data);    
});

router.get("/private", isLoggedIn ,(req, res, next)=>{
    const data = {mensajeError: "No estás loggeado"};
    if(req.session.currentUser) data.username = req.session.currentUser.username;

    res.render("users/private", data);    
});


module.exports = router;