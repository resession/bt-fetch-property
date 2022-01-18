# bt-fetch-property
bt-fetch-property is a module to add BEP 46 to webtorrent/bittorrent-dht

`const {BTFetchProperty, verify} = require("bt-fetch-property")`
the above line imports BTFetchProperty and the verify function for bittorrent-dht, verify function does not need to be imported if you are not passing in a bittorrent-dht instance

`const btfetchProperty = new BTFetchProperty({folder: someDirectory, files: someFolderNameForData, dht: webTorrentDhtInstance})`
these options are optional and not required
folder: the main directory where the module will be saving data, string
files: this will be the name of the directory which will hold publishing data, string
dht: webtorrent.dht instance, if you pass in an instance then make sure you import and use the verify function like `new Webtorrent({dht: {verify}})`, object
extra info: folder is the main directory, files is the name of the actual directory where data will be saved, like this -> folder/files

`btfetchProperty.shred(address, (error, data) => {})`
shred function removes publishing data
address: is the public key which will also be the name of the file in the files directory, string
error: error with removing the data
data: the address is sent back, meaning the data has been successfully deleted, string
extra info: publishing data includes things like the address, signature, the sequence, infohash

`btfetchProperty.resolve(address, (error, data) => {})`
resolve function resolves a address
address: is the public key, string
error: error with resolving the address
data: this will be an object containing the following keys, `{magnet, address, infoHash, sequence, stuff, sig}`, magnet is the magnet link, address is the public key, infoHash is the infohash, sequence is the sequence of the data, stuff is any other metadata that was found in the dht, sig is the signature of the data, there are couple of other keys(side, netdata) but they are only used internally for other things, object

`btfetchProperty.ownData(address, infoHash, (error, data) => {})`
ownData function is used to check and make sure the signature of a previously published data matches of the infoHash provided
address: is the public key, string
infoHash: 40 character infohash, string
error: error with matching the signature
data: the publishing data that matches the signature of the given infoHash, object

`btfetchProperty.publish(address, secret, text, (error, data) => {})`
publish function is used to publish data
address: is the public key, string
secret: is the private key, string
text: data that will be published, must be an object and must have at least 1 key with the name 'ih' which will be the 40 character infohash, object
error: error with publishing the data
data: this will be an object containing the following keys, `{magnet, address, infoHash, sequence, stuff, sig}`, magnet is the magnet link, address is the public key, infoHash is the infohash, sequence is the sequence of the data, stuff is any other metadata/keys that is found along with ih, sig is the signature of the data, object

more to come