const NodeCache = require('node-cache')
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')
const uuidv4 = require('uuid/v4')
const crypto = require('crypto')

const cache = new NodeCache({
  stdTTL: 600
})

const secret = uuidv4()

class EthAuth {
  constructor(options) {
    return (req, res, next) => {
      const DEFAULT_OPTIONS = {
        signature: 'Signature',
        message: 'Message',
        address: 'Address',
        banner: 'eth-auth'
      }

      this.options = Object.assign(
        DEFAULT_OPTIONS,
        options
      )

      const address = req.params[this.options.address]
      let message = req.params[this.options.message]
      const signature = req.params[this.options.signature]

      if (address) {
        if (ethUtil.isValidAddress(address)) {
          message = this.createMessage(address)

          req.ethAuth = {
            message
          }
        }
      }
      else if (message && signature) {
        const recoveredAddress = this.confirmMessage(message, signature)

        req.ethAuth = {
          recoveredAddress
        }
      }

      next()
    }
  }

  createMessage(address) {
    const uuid = uuidv4()
    const message = crypto.createHmac('sha256', secret)
                       .update(address + uuid)
                       .digest('hex')

    const data = [{
      type: 'string',
      name: 'banner',
      value: this.options.banner
    }, {
      type: 'string',
      name: 'message',
      value: message
    }]

    cache.set(address.toLowerCase(), message)

    return data
  }

  confirmMessage(message, signature) {
    const data = [{
      type: 'string',
      name: 'banner',
      value: this.options.banner
    }, {
      type: 'string',
      name: 'message',
      value: message
    }]

    const sig = signature

    const recoveredAddress = sigUtil.recoverTypedSignature({
      data,
      sig
    })

    const storedAddress = cache.get(recoveredAddress.toLowerCase())

    if (storedAddress === message) {
      cache.del(recoveredAddress.toLowerCase())
      return recoveredAddress
    }

    return false
  }
}

module.exports = EthAuth
