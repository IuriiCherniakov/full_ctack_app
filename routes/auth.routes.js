const {Router} = require('express')
const router = Router()
const User = require('../models/User')
const bcrypt = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')

// /api/auth/register
router.post(
    '/register',
    [
        check('email', 'Wrong email').isEmail(),
        check('password', 'Min password length is 6 characters').isLength({min: 6})
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req)

            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Wrong registration data'
                })
            }

            const {email, password} = req.body

            const candidate = await User.findOne({email: email})

            if (candidate) {
                return res.status(400).json({message: 'This User is already created'})
            }
            const hashedPassword = await bcrypt.hash(password, 12)
            const user = new User({email: email, password: hashedPassword})

            await user.save()

            res.status(201).json({message: 'User created'})

        } catch (e) {
            res.status(500).json({message: 'Something wrong, try again...'})
        }
    })

// /api/auth/resiter
router.post(
    '/login',
    [
        check('email', 'Type correct email').normalizeEmail().isEmail,
        check('password', 'Type password').exists()
    ],

    async (req, res) => {
        try {
            const errors = validationResult(req)
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Login error'
                })
            }
        } catch (e) {
            res.status(500).json({
                message: 'Something wrong, try again...'
            })
        }

        const {email, password} = req.body

        const user = await User.findOne({email})

        if (!user) {
            return res.status(400).json({message: 'User not found'})
        }

        const isMatchPasswords = await bcrypt.compare(password, user.password)

        if (!isMatchPasswords) {
            return res.status(400).json({message: 'Password is incorrect, try again'})
        }

        const token = jwt.sign(
            {userId: user.id},
            config.get('jwtSecret'),
            {expiresIn: '1h'}
        )

        res.json({token, userId: user.id})


    })


module.exports = router;