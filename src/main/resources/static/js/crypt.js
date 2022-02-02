
encodeAES = function(value) {

    var strKey = getKey();
    if (strKey.length < 16) {
        var len = strKey.length;
        for(var i = 0; i < 16 - len; i++) {
            strKey = strKey + '\u0000';
        }
    } else if (strKey.length > 32) {
        strKey = strKey.substring(0, 32);
    }

    if (value.length < 16) {
        var len = value.length;
        for(var i = 0; i < 16 - len; i++) {
            value = value + '\u0000';
        }
    }

    if ((value.length % 16) != 0) {
        var n = Math.round(value.length / 16) + 1;
        var remainder = n * 16;
        var len = value.length;
        for(var i = 0; i < remainder - len; i++) {
            value = value + '\u0000';
        }
    }

    var key = AES.Codec.strToWords(strKey);

    var cipher = new AES.ECB(key);
    var block = AES.Codec.strToWords(value);
    var retval = Int32ArrayToString(cipher.encrypt(block));
    return retval;
};


decodeAES = function(encoded, strKey) {
    var key = AES.Codec.strToWords(strKey);
    var cipher = new AES.ECB(key);
    var decoded = stringToInt32Array(encoded);
    var data = decoded;
    return Int32ArrayToString(cipher.decrypt(data));
}

encodeRSA = function(value) {
    var pubKey = getKey();
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey(pubKey);
    var encrypted = encrypt.encrypt(value);
    return encrypted;
};

stringToInt32Array = function(str) {
    var arr = [];

    for (var i = 0; i < str.length; i+=4) {
        var b1 = str.charCodeAt(i);
        var b2 = str.charCodeAt(i + 1);
        var b3 = str.charCodeAt(i + 2);
        var b4 = str.charCodeAt(i + 3);
        var res = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
        arr.push(res);
    }
    return arr;
}



Int32ArrayToString = function(wordArray) {
    var len = wordArray.length;
    var binary = '';
    for(var i = 0; i < len; i++) {
        var b = wordArray[i] >> 24;
        binary += String.fromCharCode(b);

        b = (wordArray[i] >> 16) & 0x000000FF;
        binary += String.fromCharCode(b);

        b = (wordArray[i] >> 8) & 0x000000FF;
        binary += String.fromCharCode(b);

        b = wordArray[i] & 0x000000FF;
        binary += String.fromCharCode(b);
    }

    return binary;
}

getKey = function() {
    return httpGet('/secure/key');
};

httpGet = function(getUrl) {
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", getUrl, false);
    xmlHttp.send(null);
    return xmlHttp.responseText;
}