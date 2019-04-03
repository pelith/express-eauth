const NodeCache = require('node-cache')
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')
const uuidv4 = require('uuid/v4')
const crypto = require('crypto')

const cache = new NodeCache({
  stdTTL: 600
})

const secret = uuidv4()

class Eauth {
  constructor(options) {
    return (req, res, next) => {
      const DEFAULT_OPTIONS = {
        signature: 'Signature',
        message: 'Message',
        address: 'Address',
        banner: 'Eauth',
        method: 'eth_signTypedData'
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
          if ( this.options.method === 'eth_signTypedData' ) {
            message = this.createTypedDataSignMessage(address)
          } 
          else if ( this.options.method === 'personal_sign' ) {
            message = this.createPersonalSignMessage(address)
          }
          
          req.Eauth = {
            message
          }
        }
      }
      else if (message && signature) {
        let recoveredAddress = ''
        if ( this.options.method === 'eth_signTypedData' ) {
          recoveredAddress = this.confirmTypedDataSignMessage(message, signature)
        } 
        else if ( this.options.method === 'personal_sign' ) {
          recoveredAddress = this.confirmPersonalSignMessage(message, signature)
        }        

        req.Eauth = {
          recoveredAddress
        }
      }

      next()
    }
  }

  createPersonalSignMessage(address) {
    const uuid = uuidv4()
    const message = crypto.createHmac('sha256', secret)
                       .update(address + uuid)
                       .digest('hex')

    cache.set(address.toLowerCase(), message)

    return message
  } 

  confirmPersonalSignMessage(message, signature) {
    const recoveredAddress = sigUtil.recoverPersonalSignature({
      data: message,
      sig: signature
    })

    const storedMessage = cache.get(recoveredAddress.toLowerCase())

    if (storedMessage === message) {
      cache.del(recoveredAddress.toLowerCase())
      return recoveredAddress
    }

    return false
  }

  createTypedDataSignMessage(address) {
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

  confirmTypedDataSignMessage(message, signature) {
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

module.exports = Eauth
