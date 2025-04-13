import express from 'express'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()
const router = express.Router()

const JWT_SECRET = process.env.JWT_SECRET

//ROTA DE CADASTRO: 
router.post('/cadastro', async (req, res) => {

  try{
  const user = req.body

  const salt = await bcrypt.genSalt(10)
  const hashPassword = await bcrypt.hash(user.password, salt)

  const userDB = await prisma.user.create({
    data: {
      email: user.email,
      name: user.name,
      password: hashPassword,
    }
  })
  res.status(201).json(userDB)
} 
  catch(err) {
    res.status(500).json({message: "Erro no servidor tente novamente"})
  }
}) 

//ROTA DE LOGIN: 

router.post('/login', async (req, res) => {
    
  try{
  const userInfo = req.body

  // BUSCA O USUÁRIO NO BANCO DE DADOS
  const user = await prisma.user.findUnique({
    where: {email: userInfo.email},
  })

  // VERIFICA SE O USUÁRIO EXISTE DENTRO DO BANCO
  if(!user){
    return res.status(404).json({message: "Usuário não encontrado!"})
  }

  // COMPARA A SENHA DO BANCO COM A QUE O USUÁRIO DIGITOU
  const isMatch = await bcrypt.compare(userInfo.password, user.password)

  if (!isMatch){
    return res.status(400).json({message: "Senha inválida!"})
  }

  // GERAR O TOKEN JWT

  const token = jwt.sign({id: user.id}, JWT_SECRET, {expiresIn: '1d'})

  res.status(200).json(token)
  }  catch(err) {
    res.status(500).json({message: "Erro no servidorm tente novamente" })
  }
})


export default router

