const express = require('express');
const LoginController = require('../controllers/LoginController');

const router = express.Router();

router.get('/login', LoginController.login);
router.post('/login', LoginController.auth);
router.get('/register', LoginController.register);
router.post('/register', LoginController.storeUser);
router.get('/logout', LoginController.logout);
router.get('/Historial', LoginController.historial);
router.post('/Historial', LoginController.auth);
router.get('/transferencia', LoginController.transferencia);
router.post('/transferencia', LoginController.auth);

module.exports= router