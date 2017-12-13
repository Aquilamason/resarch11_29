var certificateBuffer = new ArrayBuffer(0);


window.onload = function(){
  document.getElementById('create').onclick = function(){
    selectfunction('create_message');
  }
}

function selectfunction(mes){
  if (mes === 'create_message') {
    console.log("yes");
    createpkcs7();
  }
}

function stringToArrayBuffer(str) {
    var stringLength = str.length;

    var resultBuffer = new ArrayBuffer(stringLength);
    var resultView = new Uint8Array(resultBuffer);

    for (var i = 0; i < stringLength; i++) {
      resultView[i] = str.charCodeAt(i);
    }return resultBuffer;
  }

function formatPEM(pemString) {
    var stringLength = pemString.length;
    var resultString = "";

    for (var i = 0, count = 0; i < stringLength; i++, count++) {
      if (count > 63) {
        resultString = resultString + "\n";
        count = 0;
      }

      resultString = "" + resultString + pemString[i];
    }

    return resultString;
  }

function createpkcs7(){
  var cer = document.getElementById('cer').innerHTML;
  var privatekey = document.getElementById('pri').innerHTML;

  /*var p7 = forge.pkcs7.createEnvelopedData();
  var cert = forge.pki.certificateFromPem(cer);
  p7.addRecipient(cert);
  p7.content = forge.util.createBuffer('Hello');
  p7.encrypt();
  console.log(p7);

  var clearEncodedCertificate = cer.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, "");
  certificateBuffer = stringToArrayBuffer(window.atob(clearEncodedCertificate));

  var asn1 = fromBER(certificateBuffer);
  var certSimpl = new Certificate({ schema: asn1.result });
  var pri = document.getElementById('pri').innerHTML;

  console.log(certificateBuffer);
  console.log(p7);*/

  var p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer('Some.', 'utf8');
  p7.addCertificate(cer);
  p7.addSigner({
    key: privatekey,
    certificate: cer,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [{
      type: forge.pki.oids.contentType,
      value: forge.pki.oids.data
    }, {
        type: forge.pki.oids.messageDigest
      // value will be auto-populated at signing time
    }, {
        type: forge.pki.oids.signingTime,
    // value can also be auto-populated at signing time
        value: new Date()
    }]
  });
  p7.sign();
  var pem = forge.pkcs7.messageToPem(p7);
  //console.log(pem);
  var p7pem = pem.replace(/(-----(BEGIN|END)( NEW)? PKCS7-----|\n)/g, "");
  console.log(p7pem);
  var resultString = "";
  resultString = "" + resultString + formatPEM(p7pem);
  //console.log(resultString);
  var e = document.getElementById("message");
  e.value = resultString;
  //console.log(p7);
  createmail(p7pem);
  //console.log(createmail(resultString));
  /*var p8 = forge.pkcs7.messageFromPem(pem);
  var recipient = p8.findRecipients(cer);
  var result = p8.decrypt(p8.recipients[0], privatekey);*/
}

function createmail(cms){
  var e = document.getElementById("message");
  //console.log(cms);
  /*var cmsContentSimpl = new ContentInfo();
  cmsContentSimpl.contentType = "1.2.840.113549.1.7.2";
  
  var Mimebuilder = window["emailjs-mime-builder"];
  var mimebuilder = new Mimebuilder("application/pkcs7-mime; name=smime.p7s; smime-type=signed-data")
  mimeBuilder.setHeader("from", "sender@example.com");
  mimeBuilder.setHeader("to", "recipient@example.com");
  mimeBuilder.setHeader("subject", "Example S/MIME encrypted message");
  var mimeMessage = mimeBuilder.build();*/

  var from = "From: Armin Hberling <arminha@student.ethz.ch>";
  var To = "To: recipient@example.com";
  var subject = "Subject: valid mail";
  var messageid = "Message-ID: <27789929.11157362574316.JavaMail.armin@lappi>";
  var Mimeversion = "MIME-Version: 1.0";
  var contenttype = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\""; 
  var mic = "micalg=sha1;";
  var bound =  "boundary=\"----=_Part_0_10440721.1157362574277\"";

  var bound1 = "----=_Part_0_10440721.1157362574277";
  var contenttype1 = "Content-Type: text/plain; charset=us-ascii";
  var contenttrans1 = "Content-Transfer-Encoding: 7bit";
  var content = "Some."

  var contenttype2 = "Content-Type: application/pkcs7-signature; name=smime.p7s; smime-type=signed-data";
  var contenttrans2 = "Content-Transfer-Encoding: base64";
  var contentdispo = "Content-Disposition: attachment; filename=\"smime.p7s\"";
  var contentdes = "Content-Description: S/MIME Cryptographic Signature";

  e.value = from + "\n" + To + "\n" + subject + "\n" + messageid + "\n" + Mimeversion + "\n" + contenttype + "\n" +
  mic + "\n" + bound + "\n" + "\n" + bound1 
  + "\n" + contenttype1 + "\n" + contenttrans1 + "\n" + "\n" + content + "\n" + "\n" + bound1 + "\n" +
  contenttype2 + "\n" + contenttrans2 + "\n" + contentdispo + "\n" + contentdes
  + "\n" + cms + "\n" + bound1;

}


//**************************************************************************************
  /**
  * Class from RFC5652
  */


  var ContentInfo = function () {
    //**********************************************************************************
    /**
   * Constructor for ContentInfo class
   * @param {Object} [parameters={}]
   * @property {Object} [schema] asn1js parsed value
   */
    function ContentInfo() {
      var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

      _classCallCheck(this, ContentInfo);

      //region Internal properties of the object
      /**
    * @type {string}
    * @description contentType
    */
      this.contentType = getParametersValue(parameters, "contentType", ContentInfo.defaultValues("contentType"));
      /**
    * @type {Any}
    * @description content
    */
      this.content = getParametersValue(parameters, "content", ContentInfo.defaultValues("content"));
      //endregion

      //region If input argument array contains "schema" for this object
      if ("schema" in parameters) this.fromSchema(parameters.schema);
      //endregion
    }
    //**********************************************************************************
    /**
   * Return default values for all class members
   * @param {string} memberName String name for a class member
   */


    _createClass(ContentInfo, [{
      key: "fromSchema",

      //**********************************************************************************
      /**
    * Convert parsed asn1js object into current class
    * @param {!Object} schema
    */
      value: function fromSchema(schema) {
        //region Check the schema is valid
        var asn1 = compareSchema(schema, schema, ContentInfo.schema());

        if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CMS_CONTENT_INFO");
        //endregion

        //region Get internal properties from parsed schema
        this.contentType = asn1.result.contentType.valueBlock.toString();
        this.content = asn1.result.content;
        //endregion
      }
      //**********************************************************************************
      /**
    * Convert current object to asn1js object and set correct values
    * @returns {Object} asn1js object
    */

    }, {
      key: "toSchema",
      value: function toSchema() {
        //region Construct and return new ASN.1 schema for this object
        return new Sequence({
          value: [new ObjectIdentifier({ value: this.contentType }), new Constructed({
            idBlock: {
              tagClass: 3, // CONTEXT-SPECIFIC
              tagNumber: 0 // [0]
            },
            value: [this.content] // EXPLICIT ANY value
          })]
        });
        //endregion
      }
      //**********************************************************************************
      /**
    * Convertion for the class to JSON object
    * @returns {Object}
    */

    }, {
      key: "toJSON",
      value: function toJSON() {
        var object = {
          contentType: this.contentType
        };

        if (!(this.content instanceof Any)) object.content = this.content.toJSON();

        return object;
      }
      //**********************************************************************************

    }], [{
      key: "defaultValues",
      value: function defaultValues(memberName) {
        switch (memberName) {
          case "contentType":
            return "";
          case "content":
            return new Any();
          default:
            throw new Error("Invalid member name for ContentInfo class: " + memberName);
        }
      }
      //**********************************************************************************
      /**
    * Compare values with default values for all class members
    * @param {string} memberName String name for a class member
    * @param {*} memberValue Value to compare with default value
    */

    }, {
      key: "compareWithDefault",
      value: function compareWithDefault(memberName, memberValue) {
        switch (memberName) {
          case "contentType":
            return memberValue === "";
          case "content":
            return memberValue instanceof Any;
          default:
            throw new Error("Invalid member name for ContentInfo class: " + memberName);
        }
      }
      //**********************************************************************************
      /**
    * Return value of asn1js schema for current class
    * @param {Object} parameters Input parameters for the schema
    * @returns {Object} asn1js schema object
    */

    }, {
      key: "schema",
      value: function schema() {
        var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

        //ContentInfo ::= SEQUENCE {
        //    contentType ContentType,
        //    content [0] EXPLICIT ANY DEFINED BY contentType }

        /**
     * @type {Object}
     * @property {string} [blockName]
     * @property {string} [contentType]
     * @property {string} [content]
     */
        var names = getParametersValue(parameters, "names", {});

        if ("optional" in names === false) names.optional = false;

        return new Sequence({
          name: names.blockName || "ContentInfo",
          optional: names.optional,
          value: [new ObjectIdentifier({ name: names.contentType || "contentType" }), new Constructed({
            idBlock: {
              tagClass: 3, // CONTEXT-SPECIFIC
              tagNumber: 0 // [0]
            },
            value: [new Any({ name: names.content || "content" })] // EXPLICIT ANY value
          })]
        });
      }
    }]);

    return ContentInfo;
  }();
  //**************************************************************************************







//**************************************************************************************
  /**
  * Class from RFC5652
  */


  var EnvelopedData = function () {
    //**********************************************************************************
    /**
   * Constructor for EnvelopedData class
   * @param {Object} [parameters={}]
   * @property {Object} [schema] asn1js parsed value
   */
    function EnvelopedData() {
      var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

      _classCallCheck(this, EnvelopedData);

      //region Internal properties of the object
      /**
    * @type {number}
    * @description version
    */
      this.version = getParametersValue(parameters, "version", EnvelopedData.defaultValues("version"));

      if ("originatorInfo" in parameters)
        /**
     * @type {OriginatorInfo}
     * @description originatorInfo
     */
        this.originatorInfo = getParametersValue(parameters, "originatorInfo", EnvelopedData.defaultValues("originatorInfo"));

      /**
    * @type {Array.<RecipientInfo>}
    * @description recipientInfos
    */
      this.recipientInfos = getParametersValue(parameters, "recipientInfos", EnvelopedData.defaultValues("recipientInfos"));
      /**
    * @type {EncryptedContentInfo}
    * @description encryptedContentInfo
    */
      this.encryptedContentInfo = getParametersValue(parameters, "encryptedContentInfo", EnvelopedData.defaultValues("encryptedContentInfo"));

      if ("unprotectedAttrs" in parameters)
        /**
     * @type {Array.<Attribute>}
     * @description unprotectedAttrs
     */
        this.unprotectedAttrs = getParametersValue(parameters, "unprotectedAttrs", EnvelopedData.defaultValues("unprotectedAttrs"));
      //endregion

      //region If input argument array contains "schema" for this object
      if ("schema" in parameters) this.fromSchema(parameters.schema);
      //endregion
    }

    //**********************************************************************************
    /**
   * Return default values for all class members
   * @param {string} memberName String name for a class member
   */


    _createClass(EnvelopedData, [{
      key: "fromSchema",


      //**********************************************************************************
      /**
    * Convert parsed asn1js object into current class
    * @param {!Object} schema
    */
      value: function fromSchema(schema) {
        //region Check the schema is valid
        var asn1 = compareSchema(schema, schema, EnvelopedData.schema({
          names: {
            version: "version",
            originatorInfo: "originatorInfo",
            recipientInfos: "recipientInfos",
            encryptedContentInfo: {
              names: {
                blockName: "encryptedContentInfo"
              }
            },
            unprotectedAttrs: "unprotectedAttrs"
          }
        }));

        if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CMS_ENVELOPED_DATA");
        //endregion

        //region Get internal properties from parsed schema
        this.version = asn1.result.version.valueBlock.valueDec;

        if ("originatorInfo" in asn1.result) {
          asn1.result.originatorInfo.idBlock.tagClass = 1; // UNIVERSAL
          asn1.result.originatorInfo.idBlock.tagNumber = 16; // SEQUENCE

          this.originatorInfo = new OriginatorInfo({ schema: asn1.result.originatorInfo });
        }

        this.recipientInfos = Array.from(asn1.result.recipientInfos, function (element) {
          return new RecipientInfo({ schema: element });
        });
        this.encryptedContentInfo = new EncryptedContentInfo({ schema: asn1.result.encryptedContentInfo });

        if ("unprotectedAttrs" in asn1.result) this.unprotectedAttrs = Array.from(asn1.result.unprotectedAttrs, function (element) {
          return new Attribute({ schema: element });
        });
        //endregion
      }

      //**********************************************************************************
      /**
    * Convert current object to asn1js object and set correct values
    * @returns {Object} asn1js object
    */

    }, {
      key: "toSchema",
      value: function toSchema() {
        //region Create array for output sequence
        var outputArray = [];

        outputArray.push(new Integer({ value: this.version }));

        if ("originatorInfo" in this) {
          outputArray.push(new Constructed({
            optional: true,
            idBlock: {
              tagClass: 3, // CONTEXT-SPECIFIC
              tagNumber: 0 // [0]
            },
            value: this.originatorInfo.toSchema().valueBlock.value
          }));
        }

        outputArray.push(new Set({
          value: Array.from(this.recipientInfos, function (element) {
            return element.toSchema();
          })
        }));

        outputArray.push(this.encryptedContentInfo.toSchema());

        if ("unprotectedAttrs" in this) {
          outputArray.push(new Constructed({
            optional: true,
            idBlock: {
              tagClass: 3, // CONTEXT-SPECIFIC
              tagNumber: 1 // [1]
            },
            value: Array.from(this.unprotectedAttrs, function (element) {
              return element.toSchema();
            })
          }));
        }
        //endregion

        //region Construct and return new ASN.1 schema for this object
        return new Sequence({
          value: outputArray
        });
        //endregion
      }

      //**********************************************************************************
      /**
    * Convertion for the class to JSON object
    * @returns {Object}
    */

    }, {
      key: "toJSON",
      value: function toJSON() {
        var _object = {
          version: this.version
        };

        if ("originatorInfo" in this) _object.originatorInfo = this.originatorInfo.toJSON();

        _object.recipientInfos = Array.from(this.recipientInfos, function (element) {
          return element.toJSON();
        });
        _object.encryptedContentInfo = this.encryptedContentInfo.toJSON();

        if ("unprotectedAttrs" in this) _object.unprotectedAttrs = Array.from(this.unprotectedAttrs, function (element) {
          return element.toJSON();
        });

        return _object;
      }

      //**********************************************************************************
      /**
    * Helpers function for filling "RecipientInfo" based on recipient's certificate.
    * Problem with WebCrypto is that for RSA certificates we have only one option - "key transport" and
    * for ECC certificates we also have one option - "key agreement". As soon as Google will implement
    * DH algorithm it would be possible to use "key agreement" also for RSA certificates.
    * @param {Certificate} [certificate] Recipient's certificate
    * @param {Object} [parameters] Additional parameters neccessary for "fine tunning" of encryption process
    * @param {number} [variant] Variant = 1 is for "key transport", variant = 2 is for "key agreement". In fact the "variant" is unneccessary now because Google has no DH algorithm implementation. Thus key encryption scheme would be choosen by certificate type only: "key transport" for RSA and "key agreement" for ECC certificates.
    */

    }, {
      key: "addRecipientByCertificate",
      value: function addRecipientByCertificate(certificate, parameters, variant) {
        //region Initial variables 
        var encryptionParameters = parameters || {};
        //endregion 

        //region Check type of certificate
        if (certificate.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.113549") !== -1) variant = 1; // For the moment it is the only variant for RSA-based certificates
        else {
            if (certificate.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.10045") !== -1) variant = 2; // For the moment it is the only variant for ECC-based certificates
            else throw new Error("Unknown type of certificate's public key: " + certificate.subjectPublicKeyInfo.algorithm.algorithmId);
          }
        //endregion 

        //region Initialize encryption parameters 
        if ("oaepHashAlgorithm" in encryptionParameters === false) encryptionParameters.oaepHashAlgorithm = "SHA-512";

        if ("kdfAlgorithm" in encryptionParameters === false) encryptionParameters.kdfAlgorithm = "SHA-512";

        if ("kekEncryptionLength" in encryptionParameters === false) encryptionParameters.kekEncryptionLength = 256;
        //endregion 

        //region Add new "recipient" depends on "variant" and certificate type 
        switch (variant) {
          case 1:
            // Key transport scheme
            {
              //region keyEncryptionAlgorithm
              var oaepOID = getOIDByAlgorithm({
                name: "RSA-OAEP"
              });
              if (oaepOID === "") throw new Error("Can not find OID for OAEP");
              //endregion

              //region RSAES-OAEP-params
              var hashOID = getOIDByAlgorithm({
                name: encryptionParameters.oaepHashAlgorithm
              });
              if (hashOID === "") throw new Error("Unknown OAEP hash algorithm: " + encryptionParameters.oaepHashAlgorithm);

              var hashAlgorithm = new AlgorithmIdentifier({
                algorithmId: hashOID,
                algorithmParams: new Null()
              });

              var rsaOAEPParams = new RSAESOAEPParams({
                hashAlgorithm: hashAlgorithm,
                maskGenAlgorithm: new AlgorithmIdentifier({
                  algorithmId: "1.2.840.113549.1.1.8", // id-mgf1
                  algorithmParams: hashAlgorithm.toSchema()
                })
              });
              //endregion

              //region KeyTransRecipientInfo
              var keyInfo = new KeyTransRecipientInfo({
                version: 0,
                rid: new IssuerAndSerialNumber({
                  issuer: certificate.issuer,
                  serialNumber: certificate.serialNumber
                }),
                keyEncryptionAlgorithm: new AlgorithmIdentifier({
                  algorithmId: oaepOID,
                  algorithmParams: rsaOAEPParams.toSchema()
                }),
                recipientCertificate: certificate
                // "encryptedKey" will be calculated in "encrypt" function
              });
              //endregion

              //region Final values for "CMS_ENVELOPED_DATA"
              this.recipientInfos.push(new RecipientInfo({
                variant: 1,
                value: keyInfo
              }));
              //endregion
            }
            break;
          case 2:
            // Key agreement scheme
            {
              //region RecipientEncryptedKey
              var encryptedKey = new RecipientEncryptedKey({
                rid: new KeyAgreeRecipientIdentifier({
                  variant: 1,
                  value: new IssuerAndSerialNumber({
                    issuer: certificate.issuer,
                    serialNumber: certificate.serialNumber
                  })
                })
                // "encryptedKey" will be calculated in "encrypt" function
              });
              //endregion

              //region keyEncryptionAlgorithm
              var aesKWoid = getOIDByAlgorithm({
                name: "AES-KW",
                length: encryptionParameters.kekEncryptionLength
              });
              if (aesKWoid === "") throw new Error("Unknown length for key encryption algorithm: " + encryptionParameters.kekEncryptionLength);

              var aesKW = new AlgorithmIdentifier({
                algorithmId: aesKWoid,
                algorithmParams: new Null()
              });
              //endregion

              //region KeyAgreeRecipientInfo
              var ecdhOID = getOIDByAlgorithm({
                name: "ECDH",
                kdf: encryptionParameters.kdfAlgorithm
              });
              if (ecdhOID === "") throw new Error("Unknown KDF algorithm: " + encryptionParameters.kdfAlgorithm);

              // In fact there is no need in so long UKM, but RFC2631
              // has requirement that "UserKeyMaterial" must be 512 bits long
              var ukmBuffer = new ArrayBuffer(64);
              var ukmView = new Uint8Array(ukmBuffer);
              getRandomValues(ukmView); // Generate random values in 64 bytes long buffer

              var _keyInfo = new KeyAgreeRecipientInfo({
                version: 3,
                // "originator" will be calculated in "encrypt" function because ephemeral key would be generated there
                ukm: new OctetString({ valueHex: ukmBuffer }),
                keyEncryptionAlgorithm: new AlgorithmIdentifier({
                  algorithmId: ecdhOID,
                  algorithmParams: aesKW.toSchema()
                }),
                recipientEncryptedKeys: new RecipientEncryptedKeys({
                  encryptedKeys: [encryptedKey]
                }),
                recipientCertificate: certificate
              });
              //endregion

              //region Final values for "CMS_ENVELOPED_DATA"
              this.recipientInfos.push(new RecipientInfo({
                variant: 2,
                value: _keyInfo
              }));
              //endregion
            }
            break;
          default:
            throw new Error("Unknown \"variant\" value: " + variant);
        }
        //endregion 

        return true;
      }

      //**********************************************************************************
      /**
    * Add recipient based on pre-defined data like password or KEK
    * @param {ArrayBuffer} preDefinedData ArrayBuffer with pre-defined data
    * @param {Object} parameters Additional parameters neccessary for "fine tunning" of encryption process
    * @param {number} variant Variant = 1 for pre-defined "key encryption key" (KEK). Variant = 2 for password-based encryption.
    */

    }, {
      key: "addRecipientByPreDefinedData",
      value: function addRecipientByPreDefinedData(preDefinedData, parameters, variant) {
        //region Initial variables
        var encryptionParameters = parameters || {};
        //endregion

        //region Check initial parameters
        if (preDefinedData instanceof ArrayBuffer === false) throw new Error("Please pass \"preDefinedData\" in ArrayBuffer type");

        if (preDefinedData.byteLength === 0) throw new Error("Pre-defined data could have zero length");
        //endregion

        //region Initialize encryption parameters
        if ("keyIdentifier" in encryptionParameters === false) {
          var keyIdentifierBuffer = new ArrayBuffer(16);
          var keyIdentifierView = new Uint8Array(keyIdentifierBuffer);
          getRandomValues(keyIdentifierView);

          encryptionParameters.keyIdentifier = keyIdentifierBuffer;
        }

        if ("hmacHashAlgorithm" in encryptionParameters === false) encryptionParameters.hmacHashAlgorithm = "SHA-512";

        if ("iterationCount" in encryptionParameters === false) encryptionParameters.iterationCount = 2048;

        if ("keyEncryptionAlgorithm" in encryptionParameters === false) {
          encryptionParameters.keyEncryptionAlgorithm = {
            name: "AES-KW",
            length: 256
          };
        }

        if ("keyEncryptionAlgorithmParams" in encryptionParameters === false) encryptionParameters.keyEncryptionAlgorithmParams = new Null();
        //endregion

        //region Add new recipient based on passed variant
        switch (variant) {
          case 1:
            // KEKRecipientInfo
            {
              //region keyEncryptionAlgorithm
              var kekOID = getOIDByAlgorithm(encryptionParameters.keyEncryptionAlgorithm);
              if (kekOID === "") throw new Error("Incorrect value for \"keyEncryptionAlgorithm\"");
              //endregion

              //region KEKRecipientInfo
              var keyInfo = new KEKRecipientInfo({
                version: 4,
                kekid: new KEKIdentifier({
                  keyIdentifier: new OctetString({ valueHex: encryptionParameters.keyIdentifier })
                }),
                keyEncryptionAlgorithm: new AlgorithmIdentifier({
                  algorithmId: kekOID,
                  /*
          For AES-KW params are NULL, but for other algorithm could another situation.
          */
                  algorithmParams: encryptionParameters.keyEncryptionAlgorithmParams
                }),
                preDefinedKEK: preDefinedData
                // "encryptedKey" would be set in "ecrypt" function
              });
              //endregion

              //region Final values for "CMS_ENVELOPED_DATA"
              this.recipientInfos.push(new RecipientInfo({
                variant: 3,
                value: keyInfo
              }));
              //endregion
            }
            break;
          case 2:
            // PasswordRecipientinfo
            {
              //region keyDerivationAlgorithm
              var pbkdf2OID = getOIDByAlgorithm({
                name: "PBKDF2"
              });
              if (pbkdf2OID === "") throw new Error("Can not find OID for PBKDF2");
              //endregion

              //region Salt
              var saltBuffer = new ArrayBuffer(64);
              var saltView = new Uint8Array(saltBuffer);
              getRandomValues(saltView);
              //endregion

              //region HMAC-based algorithm
              var hmacOID = getOIDByAlgorithm({
                name: "HMAC",
                hash: {
                  name: encryptionParameters.hmacHashAlgorithm
                }
              });
              if (hmacOID === "") throw new Error("Incorrect value for \"hmacHashAlgorithm\": " + encryptionParameters.hmacHashAlgorithm);
              //endregion

              //region PBKDF2-params
              var pbkdf2Params = new PBKDF2Params({
                salt: new OctetString({ valueHex: saltBuffer }),
                iterationCount: encryptionParameters.iterationCount,
                prf: new AlgorithmIdentifier({
                  algorithmId: hmacOID,
                  algorithmParams: new Null()
                })
              });
              //endregion

              //region keyEncryptionAlgorithm
              var _kekOID = getOIDByAlgorithm(encryptionParameters.keyEncryptionAlgorithm);
              if (_kekOID === "") throw new Error("Incorrect value for \"keyEncryptionAlgorithm\"");
              //endregion

              //region PasswordRecipientinfo
              var _keyInfo2 = new PasswordRecipientinfo({
                version: 0,
                keyDerivationAlgorithm: new AlgorithmIdentifier({
                  algorithmId: pbkdf2OID,
                  algorithmParams: pbkdf2Params.toSchema()
                }),
                keyEncryptionAlgorithm: new AlgorithmIdentifier({
                  algorithmId: _kekOID,
                  /*
          For AES-KW params are NULL, but for other algorithm could be another situation.
          */
                  algorithmParams: encryptionParameters.keyEncryptionAlgorithmParams
                }),
                password: preDefinedData
                // "encryptedKey" would be set in "ecrypt" function
              });
              //endregion

              //region Final values for "CMS_ENVELOPED_DATA"
              this.recipientInfos.push(new RecipientInfo({
                variant: 4,
                value: _keyInfo2
              }));
              //endregion
            }
            break;
          default:
            throw new Error("Unknown value for \"variant\": " + variant);
        }
        //endregion
      }

      //**********************************************************************************
      /**
    * Create a new CMS Enveloped Data content with encrypted data
    * @param {Object} contentEncryptionAlgorithm WebCrypto algorithm. For the moment here could be only "AES-CBC" or "AES-GCM" algorithms.
    * @param {ArrayBuffer} contentToEncrypt Content to encrypt
    * @returns {Promise}
    */

    }, {
      key: "encrypt",
      value: function encrypt(contentEncryptionAlgorithm, contentToEncrypt) {
        var _this59 = this;

        //region Initial variables
        var sequence = Promise.resolve();

        var ivBuffer = new ArrayBuffer(16); // For AES we need IV 16 bytes long
        var ivView = new Uint8Array(ivBuffer);
        getRandomValues(ivView);

        var contentView = new Uint8Array(contentToEncrypt);

        var sessionKey = void 0;
        var encryptedContent = void 0;
        var exportedSessionKey = void 0;

        var recipientsPromises = [];

        var _this = this;
        //endregion

        //region Check for input parameters
        var contentEncryptionOID = getOIDByAlgorithm(contentEncryptionAlgorithm);
        if (contentEncryptionOID === "") return Promise.reject("Wrong \"contentEncryptionAlgorithm\" value");
        //endregion

        //region Get a "crypto" extension
        var crypto = getCrypto();
        if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
        //endregion

        //region Generate new content encryption key
        sequence = sequence.then(function () {
          return crypto.generateKey(contentEncryptionAlgorithm, true, ["encrypt"]);
        });
        //endregion
        //region Encrypt content
        sequence = sequence.then(function (result) {
          sessionKey = result;

          return crypto.encrypt({
            name: contentEncryptionAlgorithm.name,
            iv: ivView
          }, sessionKey, contentView);
        }, function (error) {
          return Promise.reject(error);
        });
        //endregion
        //region Export raw content of content encryption key
        sequence = sequence.then(function (result) {
          //region Create output OCTETSTRING with encrypted content
          encryptedContent = result;
          //endregion

          return crypto.exportKey("raw", sessionKey);
        }, function (error) {
          return Promise.reject(error);
        }).then(function (result) {
          exportedSessionKey = result;

          return true;
        }, function (error) {
          return Promise.reject(error);
        });
        //endregion
        //region Append common information to CMS_ENVELOPED_DATA
        sequence = sequence.then(function () {
          _this59.version = 2;
          _this59.encryptedContentInfo = new EncryptedContentInfo({
            contentType: "1.2.840.113549.1.7.1", // "data"
            contentEncryptionAlgorithm: new AlgorithmIdentifier({
              algorithmId: contentEncryptionOID,
              algorithmParams: new OctetString({ valueHex: ivBuffer })
            }),
            encryptedContent: new OctetString({ valueHex: encryptedContent })
          });
        }, function (error) {
          return Promise.reject(error);
        });
        //endregion

        //region Special sub-functions to work with each recipient's type
        function SubKeyAgreeRecipientInfo(index) {
          //region Initial variables
          var currentSequence = Promise.resolve();

          var ecdhPublicKey = void 0;
          var ecdhPrivateKey = void 0;

          var recipientCurve = void 0;
          var recipientCurveLength = void 0;

          var exportedECDHPublicKey = void 0;
          //endregion

          //region Get "namedCurve" parameter from recipient's certificate
          currentSequence = currentSequence.then(function () {
            var curveObject = _this.recipientInfos[index].value.recipientCertificate.subjectPublicKeyInfo.algorithm.algorithmParams;

            if (curveObject instanceof ObjectIdentifier === false) return Promise.reject("Incorrect \"recipientCertificate\" for index " + index);

            var curveOID = curveObject.valueBlock.toString();

            switch (curveOID) {
              case "1.2.840.10045.3.1.7":
                recipientCurve = "P-256";
                recipientCurveLength = 256;
                break;
              case "1.3.132.0.34":
                recipientCurve = "P-384";
                recipientCurveLength = 384;
                break;
              case "1.3.132.0.35":
                recipientCurve = "P-521";
                recipientCurveLength = 528;
                break;
              default:
                return Promise.reject("Incorrect curve OID for index " + index);
            }

            return recipientCurve;
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Generate ephemeral ECDH key
          currentSequence = currentSequence.then(function (result) {
            return crypto.generateKey({
              name: "ECDH",
              namedCurve: result
            }, true, ["deriveBits"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Export public key of ephemeral ECDH key pair
          currentSequence = currentSequence.then(function (result) {
            ecdhPublicKey = result.publicKey;
            ecdhPrivateKey = result.privateKey;

            return crypto.exportKey("spki", ecdhPublicKey);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Import recipient's public key
          currentSequence = currentSequence.then(function (result) {
            exportedECDHPublicKey = result;

            return _this.recipientInfos[index].value.recipientCertificate.getPublicKey({
              algorithm: {
                algorithm: {
                  name: "ECDH",
                  namedCurve: recipientCurve
                },
                usages: []
              }
            });
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Create shared secret
          currentSequence = currentSequence.then(function (result) {
            return crypto.deriveBits({
              name: "ECDH",
              public: result
            }, ecdhPrivateKey, recipientCurveLength);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Apply KDF function to shared secret
          currentSequence = currentSequence.then(function (result) {
            //region Get length of used AES-KW algorithm
            var aesKWAlgorithm = new AlgorithmIdentifier({ schema: _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmParams });

            var KWalgorithm = getAlgorithmByOID(aesKWAlgorithm.algorithmId);
            if ("name" in KWalgorithm === false) return Promise.reject("Incorrect OID for key encryption algorithm: " + aesKWAlgorithm.algorithmId);
            //endregion

            //region Translate AES-KW length to ArrayBuffer
            var kwLength = KWalgorithm.length;

            var kwLengthBuffer = new ArrayBuffer(4);
            var kwLengthView = new Uint8Array(kwLengthBuffer);

            for (var j = 3; j >= 0; j--) {
              kwLengthView[j] = kwLength;
              kwLength >>= 8;
            }
            //endregion

            //region Create and encode "ECC-CMS-SharedInfo" structure
            var eccInfo = new ECCCMSSharedInfo({
              keyInfo: new AlgorithmIdentifier({
                algorithmId: aesKWAlgorithm.algorithmId,
                /*
         Initially RFC5753 says that AES algorithms have absent parameters.
         But since early implementations all put NULL here. Thus, in order to be
         "backward compatible", index also put NULL here.
         */
                algorithmParams: new Null()
              }),
              entityUInfo: _this.recipientInfos[index].value.ukm,
              suppPubInfo: new OctetString({ valueHex: kwLengthBuffer })
            });

            var encodedInfo = eccInfo.toSchema().toBER(false);
            //endregion

            //region Get SHA algorithm used together with ECDH
            var ecdhAlgorithm = getAlgorithmByOID(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            if ("name" in ecdhAlgorithm === false) return Promise.reject("Incorrect OID for key encryption algorithm: " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            //endregion

            return kdf(ecdhAlgorithm.kdf, result, KWalgorithm.length, encodedInfo);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Import AES-KW key from result of KDF function
          currentSequence = currentSequence.then(function (result) {
            return crypto.importKey("raw", result, { name: "AES-KW" }, true, ["wrapKey"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Finally wrap session key by using AES-KW algorithm
          currentSequence = currentSequence.then(function (result) {
            return crypto.wrapKey("raw", sessionKey, result, { name: "AES-KW" });
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Append all neccessary data to current CMS_RECIPIENT_INFO object
          currentSequence = currentSequence.then(function (result) {
            //region OriginatorIdentifierOrKey
            var asn1 = fromBER(exportedECDHPublicKey);

            var originator = new OriginatorIdentifierOrKey();
            originator.variant = 3;
            originator.value = new OriginatorPublicKey({ schema: asn1.result });
            // There is option when we can stay with ECParameters, but here index prefer to avoid the params
            if ("algorithmParams" in originator.value.algorithm) delete originator.value.algorithm.algorithmParams;

            _this.recipientInfos[index].value.originator = originator;
            //endregion

            //region RecipientEncryptedKey
            /*
       We will not support using of same ephemeral key for many recipients
       */
            _this.recipientInfos[index].value.recipientEncryptedKeys.encryptedKeys[0].encryptedKey = new OctetString({ valueHex: result });
            //endregion
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion

          return currentSequence;
        }

        function SubKeyTransRecipientInfo(index) {
          //region Initial variables
          var currentSequence = Promise.resolve();
          //endregion

          //region Get recipient's public key
          currentSequence = currentSequence.then(function () {
            //region Get current used SHA algorithm
            var schema = _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmParams;
            var rsaOAEPParams = new RSAESOAEPParams({ schema: schema });

            var hashAlgorithm = getAlgorithmByOID(rsaOAEPParams.hashAlgorithm.algorithmId);
            if ("name" in hashAlgorithm === false) return Promise.reject("Incorrect OID for hash algorithm: " + rsaOAEPParams.hashAlgorithm.algorithmId);
            //endregion

            return _this.recipientInfos[index].value.recipientCertificate.getPublicKey({
              algorithm: {
                algorithm: {
                  name: "RSA-OAEP",
                  hash: {
                    name: hashAlgorithm.name
                  }
                },
                usages: ["encrypt", "wrapKey"]
              }
            });
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Encrypt early exported session key on recipient's public key
          currentSequence = currentSequence.then(function (result) {
            return crypto.encrypt(result.algorithm, result, exportedSessionKey);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Append all neccessary data to current CMS_RECIPIENT_INFO object
          currentSequence = currentSequence.then(function (result) {
            //region RecipientEncryptedKey
            _this.recipientInfos[index].value.encryptedKey = new OctetString({ valueHex: result });
            //endregion
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion

          return currentSequence;
        }

        function SubKEKRecipientInfo(index) {
          //region Initial variables
          var currentSequence = Promise.resolve();
          var kekAlgorithm = void 0;
          //endregion

          //region Import KEK from pre-defined data
          currentSequence = currentSequence.then(function () {
            //region Get WebCrypto form of "keyEncryptionAlgorithm"
            kekAlgorithm = getAlgorithmByOID(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            if ("name" in kekAlgorithm === false) return Promise.reject("Incorrect OID for \"keyEncryptionAlgorithm\": " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            //endregion

            return crypto.importKey("raw", new Uint8Array(_this.recipientInfos[index].value.preDefinedKEK), kekAlgorithm, true, ["wrapKey"]); // Too specific for AES-KW
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Wrap previously exported session key
          currentSequence = currentSequence.then(function (result) {
            return crypto.wrapKey("raw", sessionKey, result, kekAlgorithm);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Append all neccessary data to current CMS_RECIPIENT_INFO object
          currentSequence = currentSequence.then(function (result) {
            //region RecipientEncryptedKey
            _this.recipientInfos[index].value.encryptedKey = new OctetString({ valueHex: result });
            //endregion
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion

          return currentSequence;
        }

        function SubPasswordRecipientinfo(index) {
          //region Initial variables
          var currentSequence = Promise.resolve();
          var pbkdf2Params = void 0;
          var kekAlgorithm = void 0;
          //endregion

          //region Check that we have encoded "keyDerivationAlgorithm" plus "PBKDF2_params" in there
          currentSequence = currentSequence.then(function () {
            if ("keyDerivationAlgorithm" in _this.recipientInfos[index].value === false) return Promise.reject("Please append encoded \"keyDerivationAlgorithm\"");

            if ("algorithmParams" in _this.recipientInfos[index].value.keyDerivationAlgorithm === false) return Promise.reject("Incorrectly encoded \"keyDerivationAlgorithm\"");

            try {
              pbkdf2Params = new PBKDF2Params({ schema: _this.recipientInfos[index].value.keyDerivationAlgorithm.algorithmParams });
            } catch (ex) {
              return Promise.reject("Incorrectly encoded \"keyDerivationAlgorithm\"");
            }

            return Promise.resolve();
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Derive PBKDF2 key from "password" buffer
          currentSequence = currentSequence.then(function () {
            var passwordView = new Uint8Array(_this.recipientInfos[index].value.password);

            return crypto.importKey("raw", passwordView, "PBKDF2", false, ["deriveKey"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Derive key for "keyEncryptionAlgorithm"
          currentSequence = currentSequence.then(function (result) {
            //region Get WebCrypto form of "keyEncryptionAlgorithm"
            kekAlgorithm = getAlgorithmByOID(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            if ("name" in kekAlgorithm === false) return Promise.reject("Incorrect OID for \"keyEncryptionAlgorithm\": " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            //endregion

            //region Get HMAC hash algorithm
            var hmacHashAlgorithm = "SHA-1";

            if ("prf" in pbkdf2Params) {
              var algorithm = getAlgorithmByOID(pbkdf2Params.prf.algorithmId);
              if ("name" in algorithm === false) return Promise.reject("Incorrect OID for HMAC hash algorithm");

              hmacHashAlgorithm = algorithm.hash.name;
            }
            //endregion

            //region Get PBKDF2 "salt" value
            var saltView = new Uint8Array(pbkdf2Params.salt.valueBlock.valueHex);
            //endregion

            //region Get PBKDF2 iterations count
            var iterations = pbkdf2Params.iterationCount;
            //endregion

            return crypto.deriveKey({
              name: "PBKDF2",
              hash: {
                name: hmacHashAlgorithm
              },
              salt: saltView,
              iterations: iterations
            }, result, kekAlgorithm, true, ["wrapKey"]); // Usages are too specific for KEK algorithm
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Wrap previously exported session key (Also too specific for KEK algorithm)
          currentSequence = currentSequence.then(function (result) {
            return crypto.wrapKey("raw", sessionKey, result, kekAlgorithm);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Append all neccessary data to current CMS_RECIPIENT_INFO object
          currentSequence = currentSequence.then(function (result) {
            //region RecipientEncryptedKey
            _this.recipientInfos[index].value.encryptedKey = new OctetString({ valueHex: result });
            //endregion
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion

          return currentSequence;
        }

        //endregion

        //region Create special routines for each "recipient"
        sequence = sequence.then(function () {
          for (var i = 0; i < _this59.recipientInfos.length; i++) {
            //region Initial variables
            var currentSequence = Promise.resolve();
            //endregion

            switch (_this59.recipientInfos[i].variant) {
              case 1:
                // KeyTransRecipientInfo
                currentSequence = SubKeyTransRecipientInfo(i);
                break;
              case 2:
                // KeyAgreeRecipientInfo
                currentSequence = SubKeyAgreeRecipientInfo(i);
                break;
              case 3:
                // KEKRecipientInfo
                currentSequence = SubKEKRecipientInfo(i);
                break;
              case 4:
                // PasswordRecipientinfo
                currentSequence = SubPasswordRecipientinfo(i);
                break;
              default:
                return Promise.reject("Uknown recipient type in array with index " + i);
            }

            recipientsPromises.push(currentSequence);
          }

          return Promise.all(recipientsPromises);
        }, function (error) {
          return Promise.reject(error);
        });
        //endregion

        return sequence;
      }

      //**********************************************************************************
      /**
    * Decrypt existing CMS Enveloped Data content
    * @param {number} recipientIndex Index of recipient
    * @param {Object} parameters Additional parameters
    * @returns {Promise}
    */

    }, {
      key: "decrypt",
      value: function decrypt(recipientIndex, parameters) {
        var _this60 = this;

        //region Initial variables
        var sequence = Promise.resolve();

        var decryptionParameters = parameters || {};

        var _this = this;
        //endregion

        //region Check for input parameters
        if (recipientIndex + 1 > this.recipientInfos.length) return Promise.reject("Maximum value for \"index\" is: " + (this.recipientInfos.length - 1));
        //endregion

        //region Get a "crypto" extension
        var crypto = getCrypto();
        if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
        //endregion

        //region Special sub-functions to work with each recipient's type
        function SubKeyAgreeRecipientInfo(index) {
          //region Initial variables
          var currentSequence = Promise.resolve();

          var recipientCurve = void 0;
          var recipientCurveLength = void 0;

          var curveOID = void 0;

          var ecdhPrivateKey = void 0;
          //endregion

          //region Get "namedCurve" parameter from recipient's certificate
          currentSequence = currentSequence.then(function () {
            if ("recipientCertificate" in decryptionParameters === false) return Promise.reject("Parameter \"recipientCertificate\" is mandatory for \"KeyAgreeRecipientInfo\"");

            if ("recipientPrivateKey" in decryptionParameters === false) return Promise.reject("Parameter \"recipientPrivateKey\" is mandatory for \"KeyAgreeRecipientInfo\"");

            var curveObject = decryptionParameters.recipientCertificate.subjectPublicKeyInfo.algorithm.algorithmParams;

            if (curveObject instanceof ObjectIdentifier === false) return Promise.reject("Incorrect \"recipientCertificate\" for index " + index);

            curveOID = curveObject.valueBlock.toString();

            switch (curveOID) {
              case "1.2.840.10045.3.1.7":
                recipientCurve = "P-256";
                recipientCurveLength = 256;
                break;
              case "1.3.132.0.34":
                recipientCurve = "P-384";
                recipientCurveLength = 384;
                break;
              case "1.3.132.0.35":
                recipientCurve = "P-521";
                recipientCurveLength = 528;
                break;
              default:
                return Promise.reject("Incorrect curve OID for index " + index);
            }

            return crypto.importKey("pkcs8", decryptionParameters.recipientPrivateKey, {
              name: "ECDH",
              namedCurve: recipientCurve
            }, true, ["deriveBits"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Import sender's ephemeral public key
          currentSequence = currentSequence.then(function (result) {
            ecdhPrivateKey = result;

            //region Change "OriginatorPublicKey" if "curve" parameter absent
            if ("algorithmParams" in _this.recipientInfos[index].value.originator.value.algorithm === false) _this.recipientInfos[index].value.originator.value.algorithm.algorithmParams = new ObjectIdentifier({ value: curveOID });
            //endregion

            //region Create ArrayBuffer with sender's public key
            var buffer = _this.recipientInfos[index].value.originator.value.toSchema().toBER(false);
            //endregion

            return crypto.importKey("spki", buffer, {
              name: "ECDH",
              namedCurve: recipientCurve
            }, true, []);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Create shared secret
          currentSequence = currentSequence.then(function (result) {
            return crypto.deriveBits({
              name: "ECDH",
              public: result
            }, ecdhPrivateKey, recipientCurveLength);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Apply KDF function to shared secret
          currentSequence = currentSequence.then(function (result) {
            //region Get length of used AES-KW algorithm
            var aesKWAlgorithm = new AlgorithmIdentifier({ schema: _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmParams });

            var KWalgorithm = getAlgorithmByOID(aesKWAlgorithm.algorithmId);
            if ("name" in KWalgorithm === false) return Promise.reject("Incorrect OID for key encryption algorithm: " + aesKWAlgorithm.algorithmId);
            //endregion

            //region Translate AES-KW length to ArrayBuffer
            var kwLength = KWalgorithm.length;

            var kwLengthBuffer = new ArrayBuffer(4);
            var kwLengthView = new Uint8Array(kwLengthBuffer);

            for (var j = 3; j >= 0; j--) {
              kwLengthView[j] = kwLength;
              kwLength >>= 8;
            }
            //endregion

            //region Create and encode "ECC-CMS-SharedInfo" structure
            var eccInfo = new ECCCMSSharedInfo({
              keyInfo: new AlgorithmIdentifier({
                algorithmId: aesKWAlgorithm.algorithmId,
                /*
         Initially RFC5753 says that AES algorithms have absent parameters.
         But since early implementations all put NULL here. Thus, in order to be
         "backward compatible", index also put NULL here.
         */
                algorithmParams: new Null()
              }),
              entityUInfo: _this.recipientInfos[index].value.ukm,
              suppPubInfo: new OctetString({ valueHex: kwLengthBuffer })
            });

            var encodedInfo = eccInfo.toSchema().toBER(false);
            //endregion

            //region Get SHA algorithm used together with ECDH
            var ecdhAlgorithm = getAlgorithmByOID(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            if ("name" in ecdhAlgorithm === false) return Promise.reject("Incorrect OID for key encryption algorithm: " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            //endregion

            return kdf(ecdhAlgorithm.kdf, result, KWalgorithm.length, encodedInfo);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Import AES-KW key from result of KDF function
          currentSequence = currentSequence.then(function (result) {
            return crypto.importKey("raw", result, { name: "AES-KW" }, true, ["unwrapKey"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Finally unwrap session key
          currentSequence = currentSequence.then(function (result) {
            //region Get WebCrypto form of content encryption algorithm
            var contentEncryptionAlgorithm = getAlgorithmByOID(_this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
            if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect \"contentEncryptionAlgorithm\": " + _this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
            //endregion

            return crypto.unwrapKey("raw", _this.recipientInfos[index].value.recipientEncryptedKeys.encryptedKeys[0].encryptedKey.valueBlock.valueHex, result, { name: "AES-KW" }, contentEncryptionAlgorithm, true, ["decrypt"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion

          return currentSequence;
        }

        function SubKeyTransRecipientInfo(index) {
          //region Initial variables
          var currentSequence = Promise.resolve();
          //endregion

          //region Import recipient's private key
          currentSequence = currentSequence.then(function () {
            if ("recipientPrivateKey" in decryptionParameters === false) return Promise.reject("Parameter \"recipientPrivateKey\" is mandatory for \"KeyTransRecipientInfo\"");

            //region Get current used SHA algorithm
            var schema = _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmParams;
            var rsaOAEPParams = new RSAESOAEPParams({ schema: schema });

            var hashAlgorithm = getAlgorithmByOID(rsaOAEPParams.hashAlgorithm.algorithmId);
            if ("name" in hashAlgorithm === false) return Promise.reject("Incorrect OID for hash algorithm: " + rsaOAEPParams.hashAlgorithm.algorithmId);
            //endregion

            return crypto.importKey("pkcs8", decryptionParameters.recipientPrivateKey, {
              name: "RSA-OAEP",
              hash: {
                name: hashAlgorithm.name
              }
            }, true, ["decrypt"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Decrypt encrypted session key
          currentSequence = currentSequence.then(function (result) {
            return crypto.decrypt(result.algorithm, result, _this.recipientInfos[index].value.encryptedKey.valueBlock.valueHex);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Import decrypted session key
          currentSequence = currentSequence.then(function (result) {
            //region Get WebCrypto form of content encryption algorithm
            var contentEncryptionAlgorithm = getAlgorithmByOID(_this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
            if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect \"contentEncryptionAlgorithm\": " + _this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
            //endregion

            return crypto.importKey("raw", result, contentEncryptionAlgorithm, true, ["decrypt"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion

          return currentSequence;
        }

        function SubKEKRecipientInfo(index) {
          //region Initial variables
          var currentSequence = Promise.resolve();
          var kekAlgorithm = void 0;
          //endregion

          //region Import KEK from pre-defined data
          currentSequence = currentSequence.then(function () {
            if ("preDefinedData" in decryptionParameters === false) return Promise.reject("Parameter \"preDefinedData\" is mandatory for \"KEKRecipientInfo\"");

            //region Get WebCrypto form of "keyEncryptionAlgorithm"
            kekAlgorithm = getAlgorithmByOID(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            if ("name" in kekAlgorithm === false) return Promise.reject("Incorrect OID for \"keyEncryptionAlgorithm\": " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            //endregion

            return crypto.importKey("raw", decryptionParameters.preDefinedData, kekAlgorithm, true, ["unwrapKey"]); // Too specific for AES-KW
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Unwrap previously exported session key
          currentSequence = currentSequence.then(function (result) {
            //region Get WebCrypto form of content encryption algorithm
            var contentEncryptionAlgorithm = getAlgorithmByOID(_this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
            if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect \"contentEncryptionAlgorithm\": " + _this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
            //endregion

            return crypto.unwrapKey("raw", _this.recipientInfos[index].value.encryptedKey.valueBlock.valueHex, result, kekAlgorithm, contentEncryptionAlgorithm, true, ["decrypt"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion

          return currentSequence;
        }

        function SubPasswordRecipientinfo(index) {
          //region Initial variables
          var currentSequence = Promise.resolve();
          var pbkdf2Params = void 0;
          var kekAlgorithm = void 0;
          //endregion

          //region Derive PBKDF2 key from "password" buffer
          currentSequence = currentSequence.then(function () {
            if ("preDefinedData" in decryptionParameters === false) return Promise.reject("Parameter \"preDefinedData\" is mandatory for \"KEKRecipientInfo\"");

            if ("keyDerivationAlgorithm" in _this.recipientInfos[index].value === false) return Promise.reject("Please append encoded \"keyDerivationAlgorithm\"");

            if ("algorithmParams" in _this.recipientInfos[index].value.keyDerivationAlgorithm === false) return Promise.reject("Incorrectly encoded \"keyDerivationAlgorithm\"");

            try {
              pbkdf2Params = new PBKDF2Params({ schema: _this.recipientInfos[index].value.keyDerivationAlgorithm.algorithmParams });
            } catch (ex) {
              return Promise.reject("Incorrectly encoded \"keyDerivationAlgorithm\"");
            }

            return crypto.importKey("raw", decryptionParameters.preDefinedData, "PBKDF2", false, ["deriveKey"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Derive key for "keyEncryptionAlgorithm"
          currentSequence = currentSequence.then(function (result) {
            //region Get WebCrypto form of "keyEncryptionAlgorithm"
            kekAlgorithm = getAlgorithmByOID(_this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            if ("name" in kekAlgorithm === false) return Promise.reject("Incorrect OID for \"keyEncryptionAlgorithm\": " + _this.recipientInfos[index].value.keyEncryptionAlgorithm.algorithmId);
            //endregion

            //region Get HMAC hash algorithm
            var hmacHashAlgorithm = "SHA-1";

            if ("prf" in pbkdf2Params) {
              var algorithm = getAlgorithmByOID(pbkdf2Params.prf.algorithmId);
              if ("name" in algorithm === false) return Promise.reject("Incorrect OID for HMAC hash algorithm");

              hmacHashAlgorithm = algorithm.hash.name;
            }
            //endregion

            //region Get PBKDF2 "salt" value
            var saltView = new Uint8Array(pbkdf2Params.salt.valueBlock.valueHex);
            //endregion

            //region Get PBKDF2 iterations count
            var iterations = pbkdf2Params.iterationCount;
            //endregion

            return crypto.deriveKey({
              name: "PBKDF2",
              hash: {
                name: hmacHashAlgorithm
              },
              salt: saltView,
              iterations: iterations
            }, result, kekAlgorithm, true, ["unwrapKey"]); // Usages are too specific for KEK algorithm
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion
          //region Unwrap previously exported session key
          currentSequence = currentSequence.then(function (result) {
            //region Get WebCrypto form of content encryption algorithm
            var contentEncryptionAlgorithm = getAlgorithmByOID(_this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
            if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect \"contentEncryptionAlgorithm\": " + _this.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
            //endregion

            return crypto.unwrapKey("raw", _this.recipientInfos[index].value.encryptedKey.valueBlock.valueHex, result, kekAlgorithm, contentEncryptionAlgorithm, true, ["decrypt"]);
          }, function (error) {
            return Promise.reject(error);
          });
          //endregion

          return currentSequence;
        }

        //endregion

        //region Perform steps, specific to each type of session key encryption
        sequence = sequence.then(function () {
          //region Initial variables
          var currentSequence = Promise.resolve();
          //endregion

          switch (_this60.recipientInfos[recipientIndex].variant) {
            case 1:
              // KeyTransRecipientInfo
              currentSequence = SubKeyTransRecipientInfo(recipientIndex);
              break;
            case 2:
              // KeyAgreeRecipientInfo
              currentSequence = SubKeyAgreeRecipientInfo(recipientIndex);
              break;
            case 3:
              // KEKRecipientInfo
              currentSequence = SubKEKRecipientInfo(recipientIndex);
              break;
            case 4:
              // PasswordRecipientinfo
              currentSequence = SubPasswordRecipientinfo(recipientIndex);
              break;
            default:
              return Promise.reject("Uknown recipient type in array with index " + recipientIndex);
          }

          return currentSequence;
        }, function (error) {
          return Promise.reject(error);
        });
        //endregion

        //region Finally decrypt data by session key
        sequence = sequence.then(function (result) {
          //region Get WebCrypto form of content encryption algorithm
          var contentEncryptionAlgorithm = getAlgorithmByOID(_this60.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
          if ("name" in contentEncryptionAlgorithm === false) return Promise.reject("Incorrect \"contentEncryptionAlgorithm\": " + _this60.encryptedContentInfo.contentEncryptionAlgorithm.algorithmId);
          //endregion

          //region Get "intialization vector" for content encryption algorithm
          var ivBuffer = _this60.encryptedContentInfo.contentEncryptionAlgorithm.algorithmParams.valueBlock.valueHex;
          var ivView = new Uint8Array(ivBuffer);
          //endregion

          //region Create correct data block for decryption
          var dataBuffer = new ArrayBuffer(0);

          if (_this60.encryptedContentInfo.encryptedContent.idBlock.isConstructed === false) dataBuffer = _this60.encryptedContentInfo.encryptedContent.valueBlock.valueHex;else {
            var _iteratorNormalCompletion19 = true;
            var _didIteratorError19 = false;
            var _iteratorError19 = undefined;

            try {
              for (var _iterator19 = _this60.encryptedContentInfo.encryptedContent.valueBlock.value[Symbol.iterator](), _step19; !(_iteratorNormalCompletion19 = (_step19 = _iterator19.next()).done); _iteratorNormalCompletion19 = true) {
                var content = _step19.value;

                dataBuffer = utilConcatBuf(dataBuffer, content.valueBlock.valueHex);
              }
            } catch (err) {
              _didIteratorError19 = true;
              _iteratorError19 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion19 && _iterator19.return) {
                  _iterator19.return();
                }
              } finally {
                if (_didIteratorError19) {
                  throw _iteratorError19;
                }
              }
            }
          }
          //endregion

          return crypto.decrypt({
            name: contentEncryptionAlgorithm.name,
            iv: ivView
          }, result, dataBuffer);
        }, function (error) {
          return Promise.reject(error);
        });
        //endregion

        return sequence;
      }

      //**********************************************************************************

    }], [{
      key: "defaultValues",
      value: function defaultValues(memberName) {
        switch (memberName) {
          case "version":
            return 0;
          case "originatorInfo":
            return new OriginatorInfo();
          case "recipientInfos":
            return [];
          case "encryptedContentInfo":
            return new EncryptedContentInfo();
          case "unprotectedAttrs":
            return [];
          default:
            throw new Error("Invalid member name for EnvelopedData class: " + memberName);
        }
      }

      //**********************************************************************************
      /**
    * Compare values with default values for all class members
    * @param {string} memberName String name for a class member
    * @param {*} memberValue Value to compare with default value
    */

    }, {
      key: "compareWithDefault",
      value: function compareWithDefault(memberName, memberValue) {
        switch (memberName) {
          case "version":
            return memberValue === EnvelopedData.defaultValues(memberName);
          case "originatorInfo":
            return memberValue.certs.certificates.length === 0 && memberValue.crls.crls.length === 0;
          case "recipientInfos":
          case "unprotectedAttrs":
            return memberValue.length === 0;
          case "encryptedContentInfo":
            return EncryptedContentInfo.compareWithDefault("contentType", memberValue.contentType) && EncryptedContentInfo.compareWithDefault("contentEncryptionAlgorithm", memberValue.contentEncryptionAlgorithm) && EncryptedContentInfo.compareWithDefault("encryptedContent", memberValue.encryptedContent);
          default:
            throw new Error("Invalid member name for EnvelopedData class: " + memberName);
        }
      }

      //**********************************************************************************
      /**
    * Return value of asn1js schema for current class
    * @param {Object} parameters Input parameters for the schema
    * @returns {Object} asn1js schema object
    */

    }, {
      key: "schema",
      value: function schema() {
        var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

        //EnvelopedData ::= SEQUENCE {
        //    version CMSVersion,
        //    originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        //    recipientInfos RecipientInfos,
        //    encryptedContentInfo EncryptedContentInfo,
        //    unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

        /**
     * @type {Object}
     * @property {string} [blockName]
     * @property {string} [version]
     * @property {string} [originatorInfo]
     * @property {string} [recipientInfos]
     * @property {string} [encryptedContentInfo]
     * @property {string} [unprotectedAttrs]
     */
        var names = getParametersValue(parameters, "names", {});

        return new Sequence({
          name: names.blockName || "",
          value: [new Integer({ name: names.version || "" }), new Constructed({
            name: names.originatorInfo || "",
            optional: true,
            idBlock: {
              tagClass: 3, // CONTEXT-SPECIFIC
              tagNumber: 0 // [0]
            },
            value: OriginatorInfo.schema().valueBlock.value
          }), new Set({
            value: [new Repeated({
              name: names.recipientInfos || "",
              value: RecipientInfo.schema()
            })]
          }), EncryptedContentInfo.schema(names.encryptedContentInfo || {}), new Constructed({
            optional: true,
            idBlock: {
              tagClass: 3, // CONTEXT-SPECIFIC
              tagNumber: 1 // [1]
            },
            value: [new Repeated({
              name: names.unprotectedAttrs || "",
              value: Attribute.schema()
            })]
          })]
        });
      }
    }]);

    return EnvelopedData;
  }();
  //**************************************************************************************