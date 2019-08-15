const NodeCache = require('node-cache')
const ethAbi = require('ethereumjs-abi')
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
      else if (contract) {
        if (ethUtil.isValidAddress(contract)) {
          if (this.options.method === 'wallet_validation_typedData') {
            message = this.createContractTypedDataSignMessage(contract)
          }
          else if (this.options.method === 'wallet_validation_personal') {
            message = this.createContractPersonalSignMessage(contract)
          }
          
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
        else if (this.options.method === 'wallet_validation_typedData') {
          recoveredAddress = this.checkIsValidSignatureTypedData(message, signature)
        }
        else if (this.options.method === 'wallet_validation_personal') {
          recoveredAddress = this.checkIsValidSignaturePersonal(message, signature)
        }

        req.eauth = {
          recoveredAddress
        }
      }

      next()
    }
  }

  createContractPersonalSignMessage(contract) {
    const uuid = uuidv4()
    const message = crypto.createHmac('sha256', secret)
                       .update(contract + uuid)
                       .digest('hex')

    cache.set(message, contract.toLowerCase()) // opposite from others

    return message
  }

  checkIsValidSignaturePersonal(message, signature) {
    // console.log('------------- message: ' + message + ' -------------')
    const contractAddr = cache.get(message)
    // console.log('------------- contractAddr: ' + contractAddr + ' -------------')
    const walletContract = new this.web3.eth.Contract(ABI, contractAddr)

    const messageBuffer = ethUtil.toBuffer(message)
    const prefix = ethUtil.toBuffer('\x19Ethereum Signed Message:\n' + messageBuffer.length.toString())
    const prefixMessage = Buffer.concat([prefix, messageBuffer])

    return walletContract.methods.isValidSignature(prefixMessage, signature).call()
    .then((magicValue) => {
      // console.log('------------- magicValue: ' + magicValue + ' -------------')
      if (magicValue === '0x20c13b0b') { // '0x1626ba7e' for bytes32
        cache.del(message)
        return contractAddr
      }

      return false
    })
    .catch(err => {
      console.log(err)
      return false
    })
  }

  createContractTypedDataSignMessage(contract) {
    const uuid = uuidv4()
    const message = crypto.createHmac('sha256', secret)
                       .update(contract + uuid)
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

    cache.set(message, contract.toLowerCase()) // opposite from others

    return data
  }

  checkIsValidSignatureTypedData(message, signature) {
    // console.log('------------- message: ' + message + ' -------------')
    const contractAddr = cache.get(message)
    // console.log('------------- contractAddr: ' + contractAddr + ' -------------')
    const walletContract = new this.web3.eth.Contract(ABI, contractAddr)
    const typedData = [{
      type: 'string',
      name: 'banner',
      value: this.options.banner
    }, {
      type: 'string',
      name: 'message',
      value: message
    }]

    if (typeof typedData !== 'object' || !typedData.length)
      return false

    const data = typedData.map(function (e) {
      return e.type === 'bytes' ? ethUtil.toBuffer(e.value) : e.value
    })
    const types = typedData.map(function (e) { return e.type })
    const schema = typedData.map(function (e) {
      if (!e.name) throw error
      return e.type + ' ' + e.name
    })

    const typedMessage = ethAbi.solidityPack(
      ['bytes32', 'bytes32'],
      [
        ethAbi.soliditySHA3(new Array(typedData.length).fill('string'), schema),
        ethAbi.soliditySHA3(types, data)
      ]
    )

    return walletContract.methods.isValidSignature(typedMessage, signature).call()
    .then((magicValue) => {
      // console.log('------------- magicValue: ' + magicValue + ' -------------')
      if (magicValue === '0x20c13b0b') { // '0x1626ba7e' for bytes32
        cache.del(message)
        return contractAddr
      }

      return false
    })
    .catch(err => {
      console.log(err)
      return false
    })
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
