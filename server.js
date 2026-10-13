import express from 'express'
import mongoose, { Schema } from 'mongoose'
import cors from 'cors'
import { OAuth2Client } from 'google-auth-library'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt' // Password hashing ke liye

const app = express()
app.use(express.json())
app.use(cors())

mongoose.connect('mongodb://localhost:27017/my-app-db')
.then(() => console.log('mongo Database was connect'))
.catch((err) => console.log('not mongodb connect'))

// User Schema (password field add kar diya hai)
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: { type: String }, // Normal login/signup ke liye
    googleId: String,
    picture: String,
    role: { type: String, default: 'user' }
}); 
const User = mongoose.model('User', userSchema)

// Google ID Setup
const GOOGLE_C_ID = "757284499102-3t0lodhv10bb2orhtbpqptnkg44nti7g.apps.googleusercontent.com"
const client = new OAuth2Client(GOOGLE_C_ID)

// 1. Google Auth Route
app.post('/api/auth/google', async (req, res) => {
    try {
        const { idToken } = req.body
        if (!idToken) {
            return res.status(400).json({ message: 'Google Token is missing' })
        }

        const ticket = await client.verifyIdToken({
            idToken: idToken,
            audience: GOOGLE_C_ID,
        })
        const payload = ticket.getPayload()
        const { sub: googleId, email, name, picture } = payload;

        let user = await User.findOne({ email })

        if (!user) {
            user = new User({ name, email, googleId, picture })
            await user.save()
            console.log('new user Login : ', email)
        } else {
            console.log('Old user Login : ', email)
        }
        
        const appToken = jwt.sign(
            { userId: user._id, email: user.email },
            "MY_SECRET_KEY",
            { expiresIn: '5d' }
        );

        res.status(200).json({
            success: true,
            message: 'Sign-in successfully',
            token: appToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                picture: user.picture,
                role: user.role
            }
        })
    } catch (error) {
        console.log('api error', error)
        res.status(401).json({ message: 'authentication failed' })
    }
})

// 2. Normal Signup Route
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ success: false, message: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        user = new User({ name, email, password: hashedPassword, role: role || 'user' });
        await user.save();
        
        res.status(201).json({ success: true, message: 'Registered successfully' });
    } catch (err) {
        console.log('signup error', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
})

// 3. Normal Login Route
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !user.password) {
            return res.status(400).json({ success: false, message: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Invalid email or password' });
        }

        const appToken = jwt.sign(
            { userId: user._id, email: user.email },
            "MY_SECRET_KEY",
            { expiresIn: '5d' }
        );

        res.status(200).json({
            success: true,
            message: 'Login successfully',
            token: appToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                picture: user.picture,
                role: user.role
            }
        });
    } catch (err) {
        console.log('login error', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
})

// 4. Admin Protection Middleware (Pehle define kiya hai routes se upar)
const verifyAdmin = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) return res.status(401).json({ success: false, message: 'Unauthorized: No token provided' });

        const decoded = jwt.verify(token, "MY_SECRET_KEY");
        const user = await User.findById(decoded.userId);

        if (!user || user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Access denied: Admins only' });
        }
        req.user = user;
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
};

// 5. Get All Users Route (Admin Only)
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
    try {
        const users = await User.find({}, { password: 0 }); // Password chhupa kar bhejenge
        res.json({ success: true, users });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
})

// Make User Admin Route (Admin Only)
app.put('/api/admin/make-admin', verifyAdmin, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email dena zaroori hai!' });
        }

        const updatedUser = await User.findOneAndUpdate(
            { email: email },
            { role: 'admin' },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: 'User nahi mila is email se!' });
        }

        res.json({ success: true, message: `Success! ${email} ab admin ban gaya hai.` });
    } catch (err) {
        console.log('make-admin error', err);
        res.status(5500).json({ success: false, message: 'Server error' });
    }
});

// 6. Delete User Route (Admin Only)
app.delete('/api/admin/user/:id', verifyAdmin, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'User deleted successfully' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
})

// Protected Admin Route Example
app.get('/api/admin/data', verifyAdmin, (req, res) => {
    res.json({ success: true, message: 'Welcome Admin! Secure data loaded.' });
})

const PORT = 5500
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))