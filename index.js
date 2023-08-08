const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');

const app = express();
const uri =
  'mongodb+srv://softmuneeb:Mongo1212@mango.isigger.mongodb.net/?retryWrites=true&w=majority';

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
client
  .connect()
  .then(() => {
    console.log('Connected to MongoDB');
    startServer(); // Start the server only after connecting to MongoDB
  })
  .catch(err => console.error('Failed to connect to MongoDB', err));

app.use(express.json());

// Allow requests from specific origins or use '*' to allow any origin
const corsOptions = {
  origin: 'http://localhost:5173',
  optionsSuccessStatus: 204, // Some legacy browsers choke on 204
};
app.use(cors(corsOptions));

app.post('/login', async (req, res) => {
  try {
    const db = client.db('mydatabase');
    const users = db.collection('users');

    const user = await users.findOne({ email: req.body.email });

    if (!user) {
      return res.status(401).send('Invalid credentials');
    }

    if (await bcrypt.compare(req.body.password, user.password)) {
      // Creating a JWT
      const token = jwt.sign({ email: user.email }, 'secret_key', {
        expiresIn: '1h',
      });
      res.status(200).json({ token });
    } else {
      res.status(401).send('Invalid credentials');
    }
  } catch (error) {
    console.dir(error);
    res.status(500).send('Error logging in');
  } finally {
  }
});

app.post('/signup', async (req, res) => {
  try {
    const db = client.db('mydatabase');
    const users = db.collection('users');

    // Hashing the password
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    // Storing the new user
    await users.insertOne({ email: req.body.email, password: hashedPassword });

    res.status(201).send('User created');
  } catch (error) {
    console.dir(error);
    res.status(500).send('Error creating user');
  } finally {
  }
});

function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).send('Access Denied');

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) return res.status(403).send('Invalid Token');
    req.user = user;
    next();
  });
}

app.get('/protected-data', authenticate, (req, res) => {
  // Send some dummy data to authenticated users
  res.status(200).json({ data: 'This is some protected data' });
});

function startServer() {
  const PORT = 3000;
  app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
  });
}
