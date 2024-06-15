const express = require('express');
const app = express();
const port = process.env.PORT||4000;
const mongoose = require('mongoose');
const User = require('./modal/user.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

app.use(express.json());
app.use(cors({
    origin: 'https://registrationform-nc30.onrender.com'
}));
require('dotenv').config();

mongoose.connect(process.env.DATABASE)
    .then(()=>{
        console.log('mongdb is connected')
        app.listen(port,()=>{
            console.log(`server is running at ${port}`);
        })
    })
  .catch((error)=>{
        console.log(error);
    })

const saltRounds = 10;

async function hashPassword(password){
    try{
        const salt = await bcrypt.genSalt(saltRounds);
        const hashedPassword = await bcrypt.hash(password,salt);
        return hashedPassword;
    }catch(error){
        console.log(error);
    }
}
app.post('/signup',async(req,res)=>{
    const {name,email,password} = req.body;
    try{
        const found = await User.findOne({email:email});
        if(found){
            return res.status(400).json({message:'user already exist'})
        }
        const hashedPassword = await hashPassword(password);
    
        const newUser =  new User({
            name:name,
            email:email,
            password: hashedPassword,
        })
        await newUser.save();
        const data={
            user:{
                id:newUser._id,
                name:newUser.name,
                email:newUser.email,
            }
        }
        const token = jwt.sign(data,process.env.SECRET_KEY)
        res.json({
            success:true,
            token,
        })
    }catch(error){
        console.log(error);
        res.status(500);
    }
})

app.post('/login',async(req,res)=>{
    const {email,password}=req.body;
    try{
        const found = await User.findOne({email:email});
        if(!found){
            return res.status(400).json({message:"user not found"})
        }
        const passwordMatch = await bcrypt.compare(password,found.password);
        if(passwordMatch){
           const data = {
            user:{
                id:found.id
            }
           }
           const token = jwt.sign(data,process.env.SECRET_KEY);
           console.log(token);
           res.json({success:true,token});
        }else {
            res.status(401).json({message:'Invalid credential'})
        }
    }catch(error){
        console.log(error);
        res.status(500).json({message:"error", details: error });
    }
})