const NodeCache = require('node-cache')
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')
const uuidv4 = require('uuid/v4')
const crypto = require('crypto')
const ABI = [{"constant":true,"inputs":[{"name":"_data","type":"bytes"},{"name":"_signature","type":"bytes"}],"name":"isValidSignature","outputs":[{"name":"magicValue","type":"bytes4"}],"payable":false,"stateMutability":"view","type":"function"}]

const cache = new NodeCache({
  stdTTL: 600
})

const secret = uuidv4()

class Eauth {
  constructor(options, web3 = null) {
    return (req, res, next) => {
      const DEFAULT_OPTIONS = {
        signature: 'Signature',
        message: 'Message',
        address: 'Address',
        contract: 'Contract',
        banner: 'Eauth',
        method: 'eth_signTypedData'
      }

      this.options = Object.assign(
        DEFAULT_OPTIONS,
        options
      )

      this.web3 = web3

      const address = req.params[this.options.address]
      const contract = req.params[this.options.contract]
      let message = req.params[this.options.message]
      const signature = req.params[this.options.signature]

      if (address) {
        if (ethUtil.isValidAddress(address)) {
          if (this.options.method === 'eth_signTypedData') {
            message = this.createTypedDataSignMessage(address)
          }
          else if (this.options.method === 'personal_sign') {
            message = this.createPersonalSignMessage(address)
          }
          
          req.eauth = {
            message
          }
        }
      }
      else if (contract && this.options.method === 'wallet_validation') {
        if (ethUtil.isValidAddress(contract)) {
          message = this.createContractSignMessage(contract)
          
          req.eauth = {
            message
          }
        }
      }
      else if (message && signature) {
        let recoveredAddress = ''
        if (this.options.method === 'eth_signTypedData') {
          recoveredAddress = this.confirmTypedDataSignMessage(message, signature)
        }
        else if (this.options.method === 'personal_sign') {
          recoveredAddress = this.confirmPersonalSignMessage(message, signature)
        }
        else if (this.options.method === 'wallet_validation') {
          recoveredAddress = this.checkIsValidSignature(message, signature)
        }

        req.eauth = {
          recoveredAddress
        }
      }

      next()
    }
  }

  createContractSignMessage(contract) {
    const uuid = uuidv4()
    const message = crypto.createHmac('sha256', secret)
                       .update(contract + uuid)
                       .digest('hex')

    cache.set(message, contract) // opposite from others

    return message
  }

  checkIsValidSignature(message, signature) {
    console.log('------------- message: ' + message + ' -------------')
    const contractAddr = cache.get(message)
    console.log('------------- contractAddr: ' + contractAddr + ' -------------')
    const walletContract = new this.web3.eth.Contract(ABI, contractAddr)

    const messageBuffer = ethUtil.toBuffer(message)
    const prefix = ethUtil.toBuffer('\x19Ethereum Signed Message:\n' + messageBuffer.length.toString())
    const prefixMessage = Buffer.concat([prefix, messageBuffer])

    return walletContract.methods.isValidSignature(prefixMessage, signature).call()
    .then((magicValue) => {
      console.log('------------- magicValue: ' + magicValue + ' -------------')
      if (magicValue === '0x20c13b0b' || magicValue === '0x1626ba7e') { // given data in bytes or bytes32
        cache.del(message)
        return contractAddr
      }

      return false
    })
    .catch(console.log)
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

    const recoveredAddress = sigUtil.recoverTypedSignature({
      data: data,
      sig: signature
    })

    const storedMessage = cache.get(recoveredAddress.toLowerCase())

    if (storedMessage === message) {
      cache.del(recoveredAddress.toLowerCase())
      return recoveredAddress
    }

    return false
  }
}

module.exports = Eauth
