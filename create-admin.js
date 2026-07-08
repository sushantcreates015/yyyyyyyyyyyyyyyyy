require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  role: { type: String, default: 'customer' },
  is_active: { type: Boolean, default: true },
  expires_at: { type: Date, default: null },
  duration_minutes: { type: Number, default: 30 },
  created_at: { type: Date, default: Date.now },
  last_login: { type: Date, default: null },
  active_session_id: { type: String, default: null },
});

const User = mongoose.model('User', userSchema);

async function main() {
  try {
    await mongoose.connect(process.env.MONGO_URI);

    const username = 'admin';
    const plainPassword = 'AdminCash2026!';

    const existing = await User.findOne({ username });
    if (existing) {
      console.log('Admin already exists');
      process.exit(0);
    }

    const passwordHash = await bcrypt.hash(plainPassword, 12);

    await User.create({
      username,
      password_hash: passwordHash,
      role: 'admin',
      is_active: true,
      expires_at: null,
      duration_minutes: 999999
    });

    console.log('Admin created successfully');
    process.exit(0);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

main();