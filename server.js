require('dotenv').config();
const express = require('express');
const { authenticator } = require('otplib');
const admin = require('firebase-admin');
const app = express();
const PORT = 8080;
const API_KEY = process.env.API_KEY;  

// Inicializa o Firebase Admin com as credenciais do ambiente. Por questões de segurança, essas variáveis são armazenadas em um arquivo .env 
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
  }),
  databaseURL: process.env.FIREBASE_DATABASE_URL  
});

const db = admin.firestore();

app.get('/generate-totp', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== API_KEY) {
    return res.status(403).send('Acesso Negado');
  }

  const username = req.query.user;
  try {
    const usersRef = db.collection('users');
    const querySnapshot = await usersRef.where('usuario', '==', username).get();

    if (querySnapshot.empty) {
      return res.status(404).send('Usuário não encontrado');
    }

    const userData = querySnapshot.docs[0].data();
    const userSecret = userData.idUser; // coloca o id do usuario como segredo
    if (!userSecret) {
      return res.status(404).send('Segredo não encontrado para o usuário');
    }

    const token = authenticator.generate(userSecret);
    const timeElapsed = Math.floor(Date.now() / 1000) % 30;
    const timeRemaining = 30 - timeElapsed;

    res.json({
      username: username,
      token: token,
      tempoRestante: timeRemaining
    });
  } catch (error) {
    console.error('Erro ao acessar o Firestore:', error);
    res.status(500).send('Erro interno do servidor');
  }
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta: ${PORT}`);
});
