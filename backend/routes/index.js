const express = require('express');
const authController = require('../controller/authController');

const router = express.Router();

//testing
router.get('/test', (req, res) =>res.json({msg: 'Working!'}));

//user

//register
router.post('/register', authController.register);

//login
router.post('/login', authController.login);

//logout
//refresh

//blog
//CRUD
//create
//read all blogs
//read blog by id
//update
//delete

//comment
//create comment
//read comments by blog id

module.exports = router;