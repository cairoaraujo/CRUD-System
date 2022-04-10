//Imports
require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
var path = require('path')


app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');
//app.use('/public', express.static(path.join(__dirname, 'public')))
app.set('views', path.join(__dirname), '/views')


//config JSON Response
app.use(express.json())
app.use(bodyParser.urlencoded({extended: true}))

// Models
const User = require('./models/User.js')
const { restart } = require('nodemon')
const res = require('express/lib/response')

//ROTA PUBLICA
app.get('/', (req, res) => {
    res.render('index');
})
app.get('/auth/register', (req, res) => {
    console.log('opa')
    res.render('register');
})

// ROTA PRIVADA
app.get("/user/:id", checkToken, async (req,res) => {
    const id = req.params.id
    //check if user exists
    const user = await User.findById(id, '-password')
    if (!user){
        res.status(404).json({msg:"usuario nao encontrado"})
    }
    res.status(200).json({user})
})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({msg:"acesso negado"})
    }
    try{
        const secret = process.env.SECRET
        jwt.verify(token, secret)

        next()

    }catch(error){
        res.status(400).json({msg: "token invalido"})
    }
}


// Register User
app.post('/', async(req, res) => {
    const {name, email, password, confirmPassword} = req.body
    console.log(name)

    //VALIDATIONS
    if(!name){
        return res.status(422).json({msg:'o nome é obrigatorio'})
    }
    if(!email){
        return res.status(422).json({msg:'o email é obrigatorio'})
    }
    if(!password){
        return res.status(422).json({msg:'a senha é obrigatoria'})
    }
    if(password !== confirmPassword){
        return res.status(422).json({msg:'senhas nao conferem'})
    }

    //CHECK IF USER EXISTS
    const userExists = await User.findOne({email: email})

    if(userExists){
        return res.status(422).json({msg:'email ja existe!'})
    }

    //CREATE PASSWORD
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name, email, password:passwordHash,
    })

    try{
        await user.save()

        res.status(201).json({msg: 'usuario criado com sucesso!'})
    } catch(error){
        console.log(error)
        res.status(500).json({msg:"erro de servidor."})
    }

})


//LOGIN USER
app.post("/auth/login", async(req, res) =>{
    const{email, password} = req.body
    if(!email){
        return res.status(422).json({msg:'o email é obrigatorio'})
    }
    if(!password){
        return res.status(422).json({msg:'a senha é obrigatoria'})
    }

    //check if user exists
    const user = await User.findOne({email:email})
    if(!user){
        return res.status(404).json({msg: 'usuario nao existe'})
    }

    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword){
        return res.status(422).json({msg: 'login ou senha incorreta'})
    }
    try{
        const secret = process.env.SECRET
        const token = jwt.sign(
            {
            id: user._id,
            },
            secret,
        )
        res.status(200).json({msg:"usuario logado com sucesso.",token})

    } catch(err){
        console.log(err)
        res.status(500).json({msg:'erro'})
    }

})


//CREDENCIAIS
const dbUser = process.env.DB_USER //metodo process acessa o .enve pega as variaveis de la
const dbPass = process.env.DB_PASS

mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPass}@cluster0.irzdg.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`
)
.then(() => {
    console.log('conectou ao banco')

}).catch((err) => console.log(err))

app.listen(3000)