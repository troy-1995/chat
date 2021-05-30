const { User } = require('../models')
const bcrypt = require('bcryptjs')
const { UserInputError } = require('apollo-server')

module.exports = {
  Query: {
    getUsers: async () => {
      try {
        // find all users from the database
        const users = await User.findAll()
        return users
      } catch (error) {
        console.log(error)
      }
      return users
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

        //TODO: check if username / email exists
        const userByUsername = await User.findOne({ where: { username } })
        const userByEmail = await User.findOne({ where: { email } })

        if (userByUsername) errors.username = 'Username is taken'
        if (userByEmail) errors.email = 'Email is taken'

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
        throw new UserInputError('Bad input', { errors: err })
      }
    },
  },
}
