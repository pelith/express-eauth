const NodeCache = require('node-cache')
const ethAbi = require('ethereumjs-abi')
const ethUtil = require('ethereumjs-util')
const web3Utils = require('web3-utils')
const Web3Eth = require('web3-eth')
const sigUtil = require('eth-sig-util')
const uuidv4 = require('uuid/v4')
const crypto = require('crypto')
const ABI = [{ "constant": true, "inputs": [{ "name": "_data", "type": "bytes" }, { "name": "_signature", "type": "bytes" }], "name": "isValidSignature", "outputs": [{ "name": "magicValue", "type": "bytes4" }], "payable": false, "stateMutability": "view", "type": "function" }]

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
        contract: 'Contract',
        banner: 'Eauth',
        method: 'eth_signTypedData',
        prefix: '',
        rpc: 'https://rinkeby.infura.io/',
      }

      this.options = Object.assign(
        DEFAULT_OPTIONS,
        options
      )

      this.web3Eth = new Web3Eth(this.options.rpc)

      const address = req.params[this.options.address]
      const contract = req.params[this.options.contract]
      let message = req.params[this.options.message]
      const signature = req.params[this.options.signature]
      const chainId = parseInt(req.headers['chainid'])

      if (address) {
        if (ethUtil.isValidAddress(address)) {
          if (this.options.method === 'eth_signTypedData') {
            message = this.createTypedDataSignMessage(address)
          }
          else if (this.options.method === 'eth_signTypedData_v4') {
            message = this.createTypedDataSignMessageV4(address, chainId)
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
          else if (this.options.method === 'wallet_validation' || this.options.method === 'wallet_validation_personal') {
            message = this.createContractSignMessage(contract)
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
        else if (this.options.method === 'eth_signTypedData_v4') {
          recoveredAddress = this.confirmTypedDataSignMessageV4(message, signature, chainId)
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

    cache.set(message, contract.toLowerCase()) // opposite from others

    return message
  }

  checkIsValidSignature(message, signature) {
    const contractAddr = cache.get(message)
    const walletContract = new this.web3Eth.Contract(ABI, contractAddr)
    const prefixMessage = web3Utils.utf8ToHex(this.options.prefix + message)

    return walletContract.methods.isValidSignature(prefixMessage, signature).call()
      .then((magicValue) => {
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

  checkIsValidSignaturePersonal(message, signature) {
    // console.log('------------- message: ' + message + ' -------------')
    const contractAddr = cache.get(message)
    // console.log('------------- contractAddr: ' + contractAddr + ' -------------')
    const walletContract = new this.web3Eth.Contract(ABI, contractAddr)

    const messageBuffer = ethUtil.toBuffer(web3Utils.utf8ToHex(this.options.prefix + message))
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

    const typedData = [{
      type: 'string',
      name: 'banner',
      value: this.options.banner
    }, {
      type: 'string',
      name: 'message',
      value: message
    }]

    cache.set(message, contract.toLowerCase()) // opposite from others

    return typedData
  }

  checkIsValidSignatureTypedData(message, signature) {
    // console.log('------------- message: ' + message + ' -------------')
    const contractAddr = cache.get(message)
    // console.log('------------- contractAddr: ' + contractAddr + ' -------------')
    const walletContract = new this.web3Eth.Contract(ABI, contractAddr)
    const typedData = [{
      type: 'string',
      name: 'banner',
      value: this.options.banner
    }, {
      type: 'string',
      name: 'message',
      value: this.options.prefix + message
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
      data: web3Utils.utf8ToHex(this.options.prefix + message),
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

    const typedData = [{
      type: 'string',
      name: 'banner',
      value: this.options.banner
    }, {
      type: 'string',
      name: 'message',
      value: message
    }]

    cache.set(address.toLowerCase(), message)

    return typedData
  }

  confirmTypedDataSignMessage(message, signature) {
    const typedData = [{
      type: 'string',
      name: 'banner',
      value: this.options.banner
    }, {
      type: 'string',
      name: 'message',
      value: this.options.prefix + message,
    }]

    const recoveredAddress = sigUtil.recoverTypedSignature({
      data: typedData,
      sig: signature
    })

    const storedMessage = cache.get(recoveredAddress.toLowerCase())

    if (storedMessage === message) {
      cache.del(recoveredAddress.toLowerCase())
      return recoveredAddress
    }

    return false
  }

  constructSignTypeV4Data(message, chainId = 1) {
    return {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Eauth: [
          { name: 'banner', type: 'string' },
          { name: 'message', type: 'string' },
          { name: 'token', type: 'string' },
        ],
      },
      primaryType: 'Eauth',
      domain: {
        name: 'Eauth',
        version: '1',
        chainId: chainId,
        verifyingContract: '0x0000000000000000000000000000000000000000',
      },
      message: {
        banner: this.options.banner,
        message: this.options.prefix,
        token: message,
      },
    }
  }

  createTypedDataSignMessageV4(address, chainId) {
    const uuid = uuidv4()
    const message = crypto.createHmac('sha256', secret)
      .update(address + uuid)
      .digest('hex')

    const typedData = this.constructSignTypeV4Data(message, chainId)

    cache.set(address.toLowerCase(), message)

    return typedData
  }

  confirmTypedDataSignMessageV4(message, signature, chainId) {
    const typedData = this.constructSignTypeV4Data(message, chainId)

    const recoveredAddress = sigUtil.recoverTypedSignature_v4({
      data: typedData,
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
