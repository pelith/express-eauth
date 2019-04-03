const assert = require('assert');
const Eauth = require('../');

const eauth = new Eauth({"banner": "Pelith"});

class REQ {
    constructor() {
        this.params = {}
    }
}

test('createMessage', function() {
    let req = new REQ()
    req.params = {
        'Address':'0x550890336f0b5afd85fc355351372253e2491a6e'
    }

    let res = {}
    let next = () => {}
    eauth(req,res,next)

    const regex = /\b[A-Fa-f0-9]{64}\b/
    // assert.equal(regex.test(req.eauth.message[1].value), true);
});

test('confirmMessage', function() {
    let req = new REQ()
    req.params = {
        'Message':'728b5d358098a338b6aca13e9f27369caac4acbd058c777c10ff97de83f62026',
        'Signature': '0xe7edb643682ca6dbe96a6bb4b2b7cb31fd6ac2ad5ae10282641020823a4f088863e12b13354f16837046f6f8e0a21c6c2287e6ac575c18198a8d149da0d6d9c41b'
    }

    let res = {}
    let next = () => {}
    eauth(req,res,next)
});