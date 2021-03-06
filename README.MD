# simple-sodium

Simplify encryption and decryption using Libsodium with **static** result.

## Installation

Use the package manager [npm](https://docs.npmjs.com/about-npm) to install simple-sodium.

```bash
npm install simple-sodium
```

## Usage

```js
var simple_sodium = require("simple-sodium");

async function do_encryption (key, plain_text) {
    var result = await simple_sodium.encrypt(key,plain_text);
    console.log(result);
}

//"hello" is the key, "world" is the plain text that will be encrypted

do_encryption("hello", "world");

async function do_decryption (key, chipertext) {
    var result = await simple_sodium.decrypt(key,chipertext);
    return result
}

//"578c060..." is the encrypted plain text that we encrypt using "hello" as the key

do_decryption("hello", "578c06071451279211269233b261aefc84d2d1f641").then(function (result) {
      console.log(result)
 })


async function do_oneway (plain_text, length) {
    var result = await simple_sodium.oneway(plain_text, length);
    console.log(result);   
}

//you can speficy the result length here
do_oneway("hello world", 64).then(() => 
console.log('encryption done')
);
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
