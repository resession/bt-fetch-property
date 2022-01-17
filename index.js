const DHT = require('bittorrent-dht')
const sha1 = require('simple-sha1')
const fs = require('fs-extra')
const path = require('path')
const ed = require('ed25519-supercop')
const bencode = require('bencode')
// const EventEmitter = require('events').EventEmitter

const BTPK_PREFIX = 'urn:btpk:'
const checkHash = new RegExp('^[a-fA-F0-9]{40}$')
function encodeSigData (msg) {
  const ref = { seq: msg.seq, v: msg.v }
  if (msg.salt) ref.salt = msg.salt
  return bencode.encode(ref).slice(1, -1)
}

const defOpts = {folder: __dirname, magnet: 'magnet'}

class WebProperty {
  constructor (opt = {}) {
    // super()
    if(!opt){
      opt = {}
      opt.dht = new DHT({verify: ed.verify})
    } else {
      if(!opt.dht){
        opt.dht = new DHT({verify: ed.verify})
      }
    }
    const finalOpts = {...defOpts, ...opt}
    this.dht = finalOpts.dht
    this._folder = path.resolve(finalOpts.folder) + path.sep + finalOpts.magnet
    if(!fs.pathExistsSync(this._folder)){
      fs.ensureDirSync(this._folder)
    }
  }

  shred(address, callback){
    fs.pathExists(this._folder + path.sep + address, (error, exists) => {
      if(error){
        return callback(error)
      }
      if(exists){
        fs.remove(this._folder + path.sep + address, error => {
          if(error){
            return callback(error)
          }
          return address
        })
      } else if(!exists){
        return address
      }
    })
  }

  clearData(){
    return fs.emptyDir(this._folder)
  }

  resolve (address, callback) {
    if(!callback){
      callback = () => noop
    }

    // address = this.addressFromLink(address)
    if(!address || typeof(address) !== 'string'){
      return callback(new Error('address can not be parsed'))
    }
    const addressKey = Buffer.from(address, 'hex')

    sha1(addressKey, (targetID) => {
      this.dht.get(targetID, (err, res) => {
        if(err){
          return callback(err)
        } else if(res){

            try {
              if(!checkHash.test(res.v.ih.toString('utf-8')) || !Number.isInteger(res.seq)){
                throw new Error('data is invalid')
              }
              for(const prop in res.v){
                res.v[prop] = res.v[prop].toString('utf-8')
              }
            } catch (error) {
              return callback(error)
            }
            let {ih, ...stuff} = res.v
            let main = {magnet: `magnet:?xs=${BTPK_PREFIX}${address}`, address, infoHash: ih, sequence: res.seq, stuff, sig: res.sig.toString('hex'), side: false, netdata: res}
            return callback(null, main)

        } else if(!res){
          return callback(new Error('Could not resolve address'))
        }
      })
    })
  }

  ownData(address, infoHash, callback){
    if (!callback) {
      callback = () => noop
    }
    if(!address || !infoHash){
      return callback(new Error('must have address and infohash'))
    }
    fs.pathExists(this._folder + path.sep + address, (error, exists) => {
      if(error){
        return callback(error)
      }
      if(exists){
        fs.readFile(this._folder + path.sep + address, {}, (error, data) => {
          if(error){
            return callback(error)
          } else if(data){
            data = JSON.parse(data.toString())
            if(infoHash !== data.infoHash || !ed.verify(Buffer.from(data.sig, 'hex'), encodeSigData({seq: data.sequence, v: {ih: infoHash, ...data.stuff}}), Buffer.from(data.address, 'hex'))){
              return callback(new Error('data does not match signature'))
              // fs.pathExists(this._folder + path.sep + address, (error, exists) => {
              //   if(error){
              //     return callback(error)
              //   }
              //   if(exists){
              //     fs.remove(this._folder + path.sep + address, error => {
              //       if(error){
              //         return callback(error)
              //       } else {
              //         return callback(new Error('data does not match signature'))
              //       }
              //     })
              //   } else if(!exists){
              //     return callback(new Error('data does not match signature'))
              //   }
              // })
            }
            return callback(null, data)
          } else if(!data){
            return callback(new Error('could not read data for ' + address))
          }
        })
      } else {
        return callback(new Error('could not find data for ' + address))
      }
    })
  }

  publish (address, secret, text, callback) {
    if (!callback) {
      callback = () => noop
    }
    try {
      for(let prop in text){
        if(typeof(text[prop]) !== 'string'){
          throw new Error('text data must be strings')
        }
      }
      if(!checkHash.test(text.ih)){
        throw new Error('must have infohash')
      }
    } catch (error) {
      return callback(error)
    }
    if(!address || !secret){
      return callback(new Error('must have address and secret'))
    }

    // let propertyData = this.grab(address)

    const buffAddKey = Buffer.from(address, 'hex')
    const buffSecKey = secret ? Buffer.from(secret, 'hex') : null
    const v = text
    fs.pathExists(this._folder + path.sep + address, (error, exists) => {
      if(error){
        return callback(error)
      }
      if(exists){
        fs.readFile(this._folder + path.sep + address, {}, (error, data) => {
          if(error){
            return callback(error)
          }
          if(data){
            data = JSON.parse(data.toString())
            const seq = data.sequence + 1
            const buffSig = ed.sign(encodeSigData({seq, v}), buffAddKey, buffSecKey)
            this.dht.put({k: buffAddKey, v, seq, sig: buffSig}, (putErr, hash, number) => {
              if(putErr){
                return callback(putErr)
              } else {
                let {ih, ...stuff} = text
                let main = {magnet: `magnet:?xs=${BTPK_PREFIX}${address}`, address, infoHash: ih, sequence: seq, stuff, sig: buffSig.toString('hex'), side: true}
                fs.writeFile(this._folder + path.sep + address, JSON.stringify(main), error => {
                  if(error){
                    return callback(error)
                  }
                  return callback(null, {...main, netdata: {hash, number}, secret})
                })
              }
            })
          } else {
            return callback(new Error('could not read data'))
          }
        })
      } else {
        const seq = 0
        const buffSig = ed.sign(encodeSigData({seq, v}), buffAddKey, buffSecKey)
        this.dht.put({k: buffAddKey, v, seq, sig: buffSig}, (putErr, hash, number) => {
          if(putErr){
            return callback(putErr)
          } else {
            let {ih, ...stuff} = text
            let main = {magnet: `magnet:?xs=${BTPK_PREFIX}${address}`, address, infoHash: ih, sequence: seq, stuff, sig: buffSig.toString('hex'), side: true}
            fs.writeFile(this._folder + path.sep + address, JSON.stringify(main), error => {
              if(error){
                console.log(error)
              }
              return callback(null, {...main, netdata: {hash, number}, secret})
            })
          }
        })
      }
    })
  }

  bothGetPut(data){
    return new Promise((resolve, reject) => {
      const buffAddKey = Buffer.from(data.address, 'hex')
      const buffSigData = Buffer.from(data.sig, 'hex')
      sha1(buffAddKey, (targetID) => {

        this.dht.get(targetID, (getErr, getData) => {
          if(getErr){
            console.log(getErr)
          }
          if(getData){
            this.dht.put(getData, (putErr, hash, number) => {
              if(putErr){
                reject(putErr)
              } else {
                resolve({getData, putData: {hash: hash.toString('hex'), number}})
              }
            })
          } else if(!getData){
            this.dht.put({k: buffAddKey, v: {ih: data.infoHash, ...data.stuff}, seq: data.sequence, sig: buffSigData}, (putErr, hash, number) => {
              if(putErr){
                reject(putErr)
              } else {
                resolve({hash: hash.toString('hex'), number})
              }
            })
          }
        })
      })
    })
  }

  handleData(data){
    return new Promise((resolve, reject) => {
      this.dht.put({k: Buffer.from(data.address, 'hex'), v: {ih: data.infoHash, ...data.stuff}, seq: data.sequence, sig: Buffer.from(data.sig, 'hex')}, (error, hash, number) => {
        if(error){
          reject(error)
        } else {
          resolve({hash: hash.toString('hex'), number})
        }
      })
    })
  }

  keepCurrent(address){
    // if (!callback) {
    //   callback = () => noop
    // }
    return new Promise((resolve, reject) => {
      const buffAddKey = Buffer.from(address, 'hex')

      sha1(buffAddKey, (targetID) => {
  
        this.dht.get(targetID, (getErr, getData) => {
          if (getErr) {
            reject(getErr)
          } else if(getData){
            this.dht.put(getData, (putErr, hash, number) => {
              if(putErr){
                reject(putErr)
              } else {
                resolve({getData, putData: {hash: hash.toString('hex'), number}})
              }
            })
          } else if(!getData){
            reject(new Error('could not find property'))
          }
        })
      })
    })
  }

  createKeypair () {
    let {publicKey, secretKey} = ed.createKeyPair(ed.createSeed())

    return { address: publicKey.toString('hex'), secret: secretKey.toString('hex') }
  }

  addressFromLink(link){
    if(!link || typeof(link) !== 'string'){
      return ''
    } else if(link.startsWith('bt')){
      try {
        const parsed = new URL(link)
    
        if(!parsed.hostname){
          return ''
        } else {
          return parsed.hostname
        }

      } catch (error) {
        console.log(error)
        return ''
      }
    } else if(link.startsWith('magnet')){
      try {
        const parsed = new URL(link)

        const xs = parsed.searchParams.get('xs')
  
        const isMutableLink = xs && xs.startsWith(BTPK_PREFIX)
    
        if(!isMutableLink){
          return ''
        } else {
          return xs.slice(BTPK_PREFIX.length)
        }

      } catch (error) {
        console.log(error)
        return ''
      }
    } else {
      return ''
    }
  }
}

module.exports = {WebProperty, verify: ed.verify}

function noop () {}
