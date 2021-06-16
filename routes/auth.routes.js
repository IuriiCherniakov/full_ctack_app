const {Router} = require('express')
const router = Router()
const User = require('../models/User')
const bcrypt = require('bcryptjs')

// /api/auth/register
router.post('/register', async (req, res) => {
    try {

        const {email, password} = req.body

        const candidate = await User.findOne({ email: email })

        if (candidate) {
            return res.status(400).json({ message: 'This User is already created'})
        }
        const hashedPassword =  await bcrypt.hash(password, 12)
        const user = new User ({email: email, password: hashedPassword })

        await user.save()

        res.status(201).json({ message: 'User created' })





    } catch (e) {
        res.status(500).json({message: 'Something wrong, try again...'})
    }
})

// /api/auth/resiter
router.post('/login', async (req, res) => {

})


module.exports = router;