const { User } = require('../models')
const bcrypt = require('bcryptjs')
const { UserInputError, AuthenticationError } = require('apollo-server')
const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require('../config/env.json')
const { Op } = require('sequelize')

module.exports = {
  Query: {
    getUsers: async (_, __, context) => {
      let user
      try {
        // Get the token from the headers and verify it
        if (context.req && context.req.headers.authorization) {
          const token = context.req.headers.authorization.split('Bearer ')[1]
          jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
            if (err) {
              throw new AuthenticationError('Unauthenticated')
            }
            user = decodedToken
          })
        }

        // find all users from the database except ourselves
        const users = await User.findAll({
          where: { username: { [Op.ne]: user.username } },
        })
        return users
      } catch (error) {
        console.log(error)
        throw error
      }
    },

    login: async (_, args) => {
      const { username, password } = args
      let errors = {}

      try {
        // Check if the name and password are not empty
        if (username.trim() === '')
          errors.username = 'username must not be emtpy'
        if (password === '') errors.password = 'password must not be emtpy'

        if (Object.keys(errors).length > 0) {
          throw new UserInputError('Bad input', { errors })
        }

        // Find the user in the database
        const user = await User.findOne({
          where: { username },
        })

        if (Object.keys(errors).length > 0) {
          throw new UserInputError('User not found', { errors })
        }

        // Decrypt the password and match the user.password
        const correctPassword = await bcrypt.compare(password, user.password)
        if (!correctPassword) {
          errors.password = 'Password is incorrect'
          throw new AuthenticationError('Password is incorrect', { errors })
        }

        // Create token
        const token = jwt.sign(
          {
            username,
          },
          JWT_SECRET,
          { expiresIn: 60 * 60 }
        )

        // Modify the returned user so that the createdAt will be a string
        return {
          ...user.toJSON(),
          createdAt: user.createdAt.toISOString(),
          token,
        }
      } catch (err) {
        console.log(err)
        throw err
      }
    },
  },
  Mutation: {
    register: async (_, args) => {
      let { username, email, password, confirmPassword } = args
      let errors = {}
      try {
        //TODO: Validate input data
        if (email.trim() === '') errors.email = 'email must not be empty'
        if (username.trim() === '')
          errors.username = 'username must not be empty'
        if (password.trim() === '')
          errors.password = 'password must not be empty'
        if (confirmPassword.trim() === '')
          errors.confirmPassword = 'repeat password must not be empty'

        if (password != confirmPassword)
          errors.confirmPassword = 'password must matched'

        if (Object.keys(errors).length > 0) {
          throw errors
        }
        //TODO: Hash password
        password = await bcrypt.hash(password, 6)
        //TODO: Create user
        const user = await User.create({
          username,
          email,
          password,
        })
        //TODO: Return user
        return user
      } catch (err) {
        console.log(err)
        if (err.name === 'SequelizeUniqueConstraintError') {
          err.errors.forEach(
            (e) => (errors[e.path] = `${e.path} is already taken`)
          )
        } else if (err.name === 'SequelizeValidationError') {
          err.errors.forEach((e) => (errors[e.path] = e.message))
        }

        throw new UserInputError('Bad input', { errors })
      }
    },
  },
}
