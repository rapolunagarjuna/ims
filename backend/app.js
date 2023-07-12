require('dotenv').config();
require('./db');

const express = require('express');
const cors = require('cors')
const bodyParser = require('body-parser');
const userRoutes = require('./routes/userRoutes');

const app = express();
app.use(cors({
    origin: 'http://localhost:8080' // replace with your frontend server's URL
  }))
app.use(bodyParser.json());

app.use('/api', userRoutes);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
