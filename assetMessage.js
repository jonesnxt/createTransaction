var _hash = {
		init: SHA256_init,
		update: SHA256_write,
		getBytes: SHA256_finalize
	};

function byteArrayToBigInteger(byteArray, startIndex) {
		var value = new BigInteger("0", 10);
		var temp1, temp2;
		for (var i = byteArray.length - 1; i >= 0; i--) {
			temp1 = value.multiply(new BigInteger("256", 10));
			temp2 = temp1.add(new BigInteger(byteArray[i].toString(10), 10));
			value = temp2;
		}

		return value;
	}

function simpleHash(message) {
		_hash.init();
		_hash.update(message);
		return _hash.getBytes();
	}


	 function getPublicKey(secretPhrase) {
		
			var secretPhraseBytes = converters.stringToByteArray(secretPhrase);
			var digest = simpleHash(secretPhraseBytes);
			return curve25519.keygen(digest).p;
	}


	 function getAccountIdFromPublicKey(publicKey, RSFormat) {
		var hex = converters.hexStringToByteArray(publicKey);

		_hash.init();
		_hash.update(hex);

		var account = _hash.getBytes();

		account = converters.byteArrayToHexString(account);

		var slice = (converters.hexStringToByteArray(account)).slice(0, 8);

		var accountId = byteArrayToBigInteger(slice).toString();

		if (RSFormat) {
			var address = new NxtAddress();

			if (address.set(accountId)) {
				return address.toString();
			} else {
				return "";
			}
		} else {
			return accountId;
		}
	}

	function areByteArraysEqual(bytes1, bytes2) {
		if (bytes1.length !== bytes2.length)
			return false;

		for (var i = 0; i < bytes1.length; ++i) {
			if (bytes1[i] !== bytes2[i])
				return false;
		}

		return true;
	}

	
	 function verifyBytes(signature, message, publicKey) {
		var signatureBytes = signature;
		var messageBytes = message;
		var publicKeyBytes = publicKey;
		var v = signatureBytes.slice(0, 32);
		var h = signatureBytes.slice(32);
		var y = curve25519.verify(v, h, publicKeyBytes);

		var m = simpleHash(messageBytes);

		_hash.init();
		_hash.update(m);
		_hash.update(y);
		var h2 = _hash.getBytes();

		return areByteArraysEqual(h, h2);
	}

	 function signBytes(message, secretPhrase) {
		var messageBytes = message;
		var secretPhraseBytes = converters.stringToByteArray(secretPhrase);

		var digest = simpleHash(secretPhraseBytes);
		var s = curve25519.keygen(digest).s;

		var m = simpleHash(messageBytes);

		_hash.init();
		_hash.update(m);
		_hash.update(s);
		var x = _hash.getBytes();

		var y = curve25519.keygen(x).p;

		_hash.init();
		_hash.update(m);
		_hash.update(y);
		var h = _hash.getBytes();

		var v = curve25519.sign(h, x, s);

		return (v.concat(h));
	}

	function toByteArray(long) {
    // we want to represent the input as a 8-bytes array
    var byteArray = [0, 0, 0, 0];

    for ( var index = 0; index < byteArray.length; index ++ ) {
        var byte = long & 0xff;
        byteArray [ index ] = byte;
        long = (long - byte) / 256 ;
    }

    return byteArray;
};

function toIntVal(byteArray) {
    // we want to represent the input as a 8-bytes array
    var intval = 0;

    for ( var index = 0; index < byteArray.length; index ++ ) {
    	var byt = byteArray[index] & 0xFF;
    	var value = byt * Math.pow(256, index);
    	intval += value;
    }

    return intval;
};

function pad(length, val) {
    var array = [];
    for (var i = 0; i < length; i++) {
        array[i] = val;
    }
    return array;
}

function wordBytes(word)
{
	return [(word%256), Math.floor(word/256)];
}


function assetMessageTransaction(recipient, quantityQNT, asset, message, secretPhrase)
{
	var zeroArray = [0];
	var txbytes = [];

	var type = 2;
	txbytes.push(type) // type

	var version = 1;
	var subtype = 1;
	txbytes.push(subtype + (version << 4));

	var timestamp = Math.floor(Date.now() / 1000) - 1385294400;
	txbytes = txbytes.concat(converters.int32ToBytes(timestamp));

	txbytes = txbytes.concat(wordBytes(1440));

	txbytes = txbytes.concat(getPublicKey(secretPhrase));
	var rec = new NxtAddress();
	rec.set(recipient);
	var recip = (new BigInteger(rec.account_id())).toByteArray().reverse();
	txbytes = txbytes.concat(recip);

	var amount = ((new BigInteger(String(parseInt(0))))).toByteArray().reverse();
	while(amount.length < 8) amount = amount.concat(zeroArray);
	txbytes = txbytes.concat(amount);

	var fee = (converters.int32ToBytes(100000000))
	while(fee.length < 8) fee = fee.concat(zeroArray);
	txbytes = txbytes.concat(fee);

	txbytes = txbytes.concat(pad(32, 0)); // ref full hash

	// break into signed and unsigned here

	txbytes = txbytes.concat(pad(64, 0)); // signature empty

	var appendages = 1;
	txbytes.push(appendages);
	txbytes = txbytes.concat(pad(15, 0));
	
	var assetVersion = 1;
	txbytes.push(assetVersion);

	var ast = (new BigInteger(asset)).toByteArray().reverse();
	if(ast.length == 9) ast = ast.slice(0, 8);
	while(ast.length < 8) ast = ast.concat(zeroArray);
	txbytes = txbytes.concat(ast);

	var qnt = converters.int32ToBytes(quantityQNT);
	while(qnt.length < 8) qnt = qnt.concat(zeroArray);
	txbytes = txbytes.concat(qnt);

	var messageVersion = 1;
	txbytes.push(messageVersion);

	var messageLength = wordBytes(message.length);
	txbytes = txbytes.concat(messageLength);
	txbytes.push(0); txbytes.push(128);

	var messageBytes = converters.stringToByteArray(message);
	txbytes = txbytes.concat(messageBytes);
			
	// we have a issue with validation and negatives here so we need to swap in and out of hex to get rid of negative bytes
	txbytes = converters.hexStringToByteArray(converters.byteArrayToHexString(txbytes));

	var sig = signBytes(txbytes, secretPhrase);
	var signable = txbytes.slice(0, 96).concat(sig).concat(txbytes.slice(96+64));

	return signable;		
}