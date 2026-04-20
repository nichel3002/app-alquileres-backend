const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Tesseract = require('tesseract.js');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_for_dev';

// Configuración de Cloudinary (Usa variables de entorno en producción)
// Estas deben ser configuradas en Render más adelante
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'demo',
  api_key: process.env.CLOUDINARY_API_KEY || '12345',
  api_secret: process.env.CLOUDINARY_API_SECRET || 'abcde'
});

app.use(cors());
app.use(express.json());

// ==========================================
// MIDDLEWARE DE AUTENTICACIÓN
// ==========================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Acceso denegado. No se proporcionó un token.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido o expirado.' });
    req.user = user;
    next();
  });
};

// ==========================================
// RUTAS DE USUARIOS (LOGIN / REGISTRO)
// ==========================================
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'El correo ya está registrado.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await prisma.user.create({
      data: { name, email, password: hashedPassword }
    });

    const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({ message: 'Usuario creado con éxito', token, user: { id: newUser.id, name, email } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error interno al registrar usuario.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ error: 'Credenciales inválidas.' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Credenciales inválidas.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login exitoso', token, user: { id: user.id, name: user.name, email } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error interno al iniciar sesión.' });
  }
});

// ==========================================
// CONFIGURACIÓN DE SUBIDA (En memoria para la Nube)
// ==========================================
// Usamos memoryStorage porque Render borra los archivos, los subiremos a Cloudinary
const upload = multer({ storage: multer.memoryStorage() });

// Función para calcular hash SHA-256 desde el Buffer
function calculateHashFromBuffer(buffer) {
  const hash = crypto.createHash('sha256');
  hash.update(buffer);
  return hash.digest('hex');
}

// Función para subir buffer a Cloudinary
const uploadToCloudinary = (buffer, filename) => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: 'app_alquileres', public_id: filename },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );
    uploadStream.end(buffer);
  });
};

// ==========================================
// RUTAS DE COMPROBANTES (PROTEGIDAS)
// ==========================================
app.post('/api/upload', authenticateToken, upload.single('receipt'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No se subió ningún archivo' });
    }

    const fileBuffer = req.file.buffer;
    const originalName = req.file.originalname;
    
    // 1. Calcular el Hash SHA-256 para auditoría (desde Memoria)
    const imageHash = calculateHashFromBuffer(fileBuffer);

    // Verificar si ya existe este comprobante
    const existing = await prisma.paymentReceipt.findUnique({ where: { imageHash } });
    if (existing) {
      return res.status(400).json({ error: 'Este comprobante ya fue subido anteriormente.' });
    }

    // 2. Ejecutar OCR usando Tesseract.js directamente desde el Buffer
    console.log('Procesando OCR...');
    const { data: { text } } = await Tesseract.recognize(
      fileBuffer,
      'spa+eng',
      { logger: m => console.log(m) }
    );

    // 3. Extraer valor y número de comprobante con Regex
    const amountMatch = text.match(/(?:\$|USD|S\/|Bs|€)?\s*(\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2}))/);
    const amount = amountMatch ? parseFloat(amountMatch[1].replace(/,/g, '')) : null;
    const refMatch = text.match(/(?:ref|referencia|comprobante|operaci[oó]n|nro|n[uú]mero|#)[^\d]*(\d{4,15})/i);
    const receiptNumber = refMatch ? refMatch[1] : null;

    // 4. Subir imagen a Cloudinary (Almacenamiento Permanente)
    let imageUrl = '';
    // NOTA: Si Cloudinary no está configurado (como en local inicial), guardamos una URL falsa temporal
    if (process.env.CLOUDINARY_API_KEY) {
      const uploadResult = await uploadToCloudinary(fileBuffer, `${Date.now()}-${imageHash.substring(0,6)}`);
      imageUrl = uploadResult.secure_url;
    } else {
      imageUrl = 'https://via.placeholder.com/600?text=Cloudinary+No+Configurado';
    }

    // 5. Guardar en Base de Datos asignado al Usuario
    const newReceipt = await prisma.paymentReceipt.create({
      data: {
        fileName: originalName,
        imageHash: imageHash,
        extractedText: text,
        amount: amount,
        receiptNumber: receiptNumber,
        userId: req.user.id, // ID del usuario autenticado
      }
    });

    // Agregar la URL de la imagen al resultado para la app móvil
    const responseData = { ...newReceipt, imageUrl };

    res.json({
      message: 'Comprobante procesado con éxito',
      data: responseData
    });

  } catch (error) {
    console.error('Error al procesar el comprobante:', error);
    res.status(500).json({ error: 'Error interno del servidor al procesar el archivo.' });
  }
});

app.get('/api/receipts', authenticateToken, async (req, res) => {
  try {
    // Solo devolvemos los comprobantes del usuario logueado
    const receipts = await prisma.paymentReceipt.findMany({
      where: { userId: req.user.id },
      orderBy: { uploadedAt: 'desc' }
    });
    res.json(receipts);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener el historial' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor backend corriendo en http://localhost:${PORT}`);
});
