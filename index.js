const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/' });
const fs = require('fs');

require('dotenv').config();

// User Model
const User = require('./models/User');
const Post = require('./models/Post');

const app = express();

// Middlewares
// app.use(
//   cors({ credentials: true, origin: 'https://insight-api-7biz.onrender.com' })
// );
app.use((req, res, next) => {
  res.setHeader(
    'Access-Control-Allow-Origin',
    'https://insight-ducf.onrender.com'
  );
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, PUT, DELETE, OPTIONS'
  );
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));

// connecting to DB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(process.env.PORT, (req, res) => {
      console.log(`listening to port ${process.env.PORT}`);
    });
  })
  .catch((err) => {
    console.log(err);
  });

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);
  try {
    const userDoc = await User.create({
      name,
      email,
      password: hashedPassword,
    });
    res.status(200).json(userDoc);
  } catch (err) {
    res.status(400).json({ error: err });
    // res.json({error: err});
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const userDoc = await User.findOne({ email });
  const name = userDoc?.name;
  const id = userDoc?._id;

  if (userDoc) {
    const match = await bcrypt.compare(password, userDoc.password);
    if (!match) {
      res.status(400).json({ error: 'Password does not match!' });
    } else {
      jwt.sign(
        { name, id: userDoc._id },
        process.env.JWT_SECRET,
        {},
        (err, token) => {
          if (err) {
            throw err;
          } else {
            res
              .cookie('jwt_token', token, {
                httpOnly: true,
                secure: true,
                domain: 'https://insight-api-7biz.onrender.com',
              })
              .json({
                name,
                id,
              });
          }
        }
      );
      // res.status(200).json(userDoc);
    }
  } else {
    res.status(400).json({ error: 'Email not found!' });
  }
});

app.get('/profile', (req, res) => {
  const { jwt_token } = req.cookies;
  if (jwt_token) {
    jwt.verify(jwt_token, process.env.JWT_SECRET, {}, (err, info) => {
      if (err) {
        throw err;
      } else {
        res.json(info);
      }
    });
  }
});

app.post('/logout', (req, res) => {
  // res.cookie('jwt_token', '').json('ok');
  res
    .cookie('jwt_token', '', {
      httpOnly: true,
      secure: true,
      domain: 'https://insight-api-7biz.onrender.com',
    })
    .json('ok');
});

app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  // res.json(req.file);
  const { jwt_token } = req.cookies;
  const { originalname, path } = req.file;
  const [_, extn] = originalname.split('.');
  const newPath = path + '.' + extn;
  fs.renameSync(path, newPath);
  const { title, summary, content } = req.body;
  if (jwt_token) {
    jwt.verify(jwt_token, process.env.JWT_SECRET, {}, async (err, info) => {
      if (err) {
        throw err;
      } else {
        const postDoc = await Post.create({
          title,
          summary,
          content,
          coverImg: newPath,
          author: info.id,
        });
        res.status(200).json(postDoc);
      }
    });
  }
});

app.get('/post', async (req, res) => {
  try {
    const posts = await Post.find({})
      .populate('author', ['name'])
      .sort({ createdAt: -1 });
    res.status(200).json(posts);
  } catch (err) {
    res.status(400).json({ error: err });
  }
});

app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  const postDoc = await Post.findById(id).populate('author', ['name']);
  res.json(postDoc);
});

app.post('/post/:id', uploadMiddleware.single('file'), async (req, res) => {
  const { id } = req.params;
  const { jwt_token } = req.cookies;
  if (req.file) {
    const { originalname, path } = req.file;
    const [_, extn] = originalname.split('.');
    const newPath = path + '.' + extn;
    fs.renameSync(path, newPath);
  }
  const { title, summary, content } = req.body;
  const postDoc = await Post.findById(id).populate('author', ['name']);

  if (jwt_token) {
    jwt.verify(jwt_token, process.env.JWT_SECRET, {}, async (err, info) => {
      if (err) {
        throw err;
      } else {
        if (postDoc) {
          const authorID = postDoc.author.id;
          if (authorID === info.id && req.file) {
            const updatedPostDoc = await Post.findByIdAndUpdate(id, {
              title,
              summary,
              content,
              coverImg: newPath,
              author: info.id,
            });
            res.status(200).json(updatedPostDoc);
          } else if (authorID === info.id && !req.file) {
            const updatedPostDoc = await Post.findByIdAndUpdate(id, {
              title,
              summary,
              content,
              author: info.id,
            });
            res.status(200).json(updatedPostDoc);
          } else {
            res.status(400).json({ error: 'not valid author!' });
          }
        } else {
          res.status(400).json({ error: 'not valid author!' });
        }
      }
    });
  }
});

module.exports = app;
