const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const JWT_SECRET = process.env.JWT_SECRET || 'financeflow-secret-key-change-in-production';

// Configurar transporter de email (Gmail)
const createEmailTransporter = () => {
  // Gmail app passwords podem ter espaços, remover para garantir
  const cleanPassword = process.env.EMAIL_PASS ? process.env.EMAIL_PASS.replace(/\s+/g, '') : '';
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: cleanPassword
    }
  });
};

// Hash de senha
const hashPassword = async (password) => {
  return await bcrypt.hash(password, 10);
};

// Comparar senha
const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

// Gerar token JWT
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
};

// Verificar token JWT
const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
};

// Middleware de autenticação
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Token inválido' });
  }

  req.userId = decoded.userId;
  next();
};

// Enviar email de recuperação de senha
const sendPasswordResetEmail = async (email, resetToken) => {
  try {
    const transporter = createEmailTransporter();
    
    const resetUrl = `https://8080-ii7txjjve53nzb4vbd2mr-99da189b.us2.manus.computer/reset-password?token=${resetToken}`;
    
    const mailOptions = {
      from: `"FinanceFlow" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Recuperação de Senha - FinanceFlow',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 28px;">🔐 FinanceFlow</h1>
          </div>
          <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px;">
            <h2 style="color: #1f2937; margin-top: 0;">Recuperação de Senha</h2>
            <p style="color: #4b5563; font-size: 16px; line-height: 1.6;">
              Você solicitou a recuperação de senha para sua conta no FinanceFlow.
            </p>
            <p style="color: #4b5563; font-size: 16px; line-height: 1.6;">
              Clique no botão abaixo para redefinir sua senha:
            </p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetUrl}" style="display: inline-block; padding: 14px 32px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
                Redefinir Senha
              </a>
            </div>
            <p style="color: #6b7280; font-size: 14px; line-height: 1.6;">
              ⏰ Este link expira em <strong>1 hora</strong>.
            </p>
            <p style="color: #6b7280; font-size: 14px; line-height: 1.6;">
              Se você não solicitou esta recuperação, ignore este email com segurança.
            </p>
            <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
            <p style="color: #9ca3af; font-size: 12px; text-align: center; margin: 0;">
              FinanceFlow - Gestão Financeira Multi-Moeda<br>
              © 2026 Todos os direitos reservados
            </p>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('✅ Email de recuperação enviado para:', email);
    return true;
  } catch (error) {
    console.error('❌ Erro ao enviar email:', error.message);
    if (error.response) {
      console.error('Detalhes:', error.response);
    }
    return false;
  }
};

// Gerar token de reset
const generateResetToken = () => {
  return uuidv4();
};

module.exports = {
  hashPassword,
  comparePassword,
  generateToken,
  verifyToken,
  authMiddleware,
  sendPasswordResetEmail,
  generateResetToken
};
