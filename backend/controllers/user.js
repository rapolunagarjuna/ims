const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

require('dotenv').config(); // import environment variables

exports.login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'email/ password missing' });
  }
  
  // check if user exists
  const user = await User.findOne({ email });
  
  if (!user) {
    return res.status(401).json({ message: 'User not found' });
  }
  
  // check if password matches
  const isMatch = await bcrypt.compare(password, user.password);
  
  if (!isMatch) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  
  // create jwt
  const payload = { userId: user.id };
  const token = jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: '1h' });
  
  return res.json({ token });
};

exports.register = async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  // check if user already exists
  let user = await User.findOne({ email });
  
  if (user) {
    return res.status(400).json({ message: 'User already exists' });
  }

  // hash the password
  const hashedPassword = await bcrypt.hash(password, 12);
  
  // create the user
  user = new User({
    firstName,
    lastName,
    email,
    password: hashedPassword
  });

  await user.save();

  return res.status(201).json({ message: 'User registered successfully' });
};
