	window.onload = function(){
		document.getElementById('create').onclick = function(){
			selectfunction('create_cmsmessage');
		}
	}

	function selectfunction(mes){
		if (mes == 'create_cmsmessage') {
			console.log("yes");
			createCMSSigned();
		};
	}

	var cmsSignedBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CMS_Signed
	var certificateBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CERT
	var privateKeyBuffer = new ArrayBuffer(0);


	function createCMSSigned() {

		//region Decode input certificate add by mi_ya
		var encodedCertificate = document.getElementById("certificate").innerHTML;
		var clearEncodedCertificate = encodedCertificate.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, "");
		certificateBuffer = stringToArrayBuffer(window.atob(clearEncodedCertificate));

		var asn1 = fromBER(certificateBuffer);
		var certSimpl = new Certificate({ schema: asn1.result });
		//endregion 

		//region Decode input certificate add by mi_ya
		var encodedCertificate = document.getElementById("privateKey").innerHTML;
		var clearEncodedCertificate = encodedCertificate.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, "");
		privateKeyBuffer = stringToArrayBuffer(window.atob(clearEncodedCertificate));

		var asn11 = fromBER(privateKeyBuffer);
		var certSimpl11 = new Certificate({ schema: asn11.result });
		//endregion

		return createCMSSignedInternal().then(function () {
			/*var certSimplString = String.fromCharCode.apply(null, new Uint8Array(certificateBuffer));

			var resultString = "-----BEGIN CERTIFICATE-----\r\n";
			resultString = resultString + formatPEM(window.btoa(certSimplString));
			resultString = resultString + "\r\n-----END CERTIFICATE-----\r\n";

			alert("Certificate created successfully!");

			var privateKeyString = String.fromCharCode.apply(null, new Uint8Array(privateKeyBuffer));

			resultString = resultString + "\r\n-----BEGIN PRIVATE KEY-----\r\n";
			resultString = resultString + formatPEM(window.btoa(privateKeyString));
			resultString = resultString + "\r\n-----END PRIVATE KEY-----\r\n";

			document.getElementById("new_signed_data").innerHTML = resultString;

			alert("Private key exported successfully!");*/

			var signedDataString = String.fromCharCode.apply(null, new Uint8Array(cmsSignedBuffer));


			resultString = resultString + "\r\n-----BEGIN CMS-----\r\n";
			resultString = resultString + formatPEM(window.btoa(signedDataString));
			resultString = resultString + "\r\n-----END CMS-----\r\n\r\n";

			document.getElementById("after_signed_data").innerHTML = resultString;

			parseCMSSigned();

			alert("CMS Signed Data created successfully!");
		});
	}

	//*********************************************************************************
	//endregion
	//*********************************************************************************
	//region Create CMS_Signed
	//*********************************************************************************
	function createCMSSignedInternal() {
		/*//region Initial variables
		var sequence = Promise.resolve();

		var certSimpl = new Certificate();
		var cmsSignedSimpl = void 0;

		var publicKey = void 0;
		var privateKey = void 0;
		//endregion

		//region Get a "crypto" extension
		var crypto = getCrypto();
		if (typeof crypto === "undefined") return Promise.reject("No WebCrypto extension found");
		//endregion

		//region Put a static values
		certSimpl.version = 2;
		certSimpl.serialNumber = new Integer({ value: 1 });
		certSimpl.issuer.typesAndValues.push(new AttributeTypeAndValue({
			type: "2.5.4.6", // Country name
			value: new PrintableString({ value: "RU" })
		}));
		certSimpl.issuer.typesAndValues.push(new AttributeTypeAndValue({
			type: "2.5.4.3", // Common name
			value: new BmpString({ value: "Test" })
		}));
		certSimpl.subject.typesAndValues.push(new AttributeTypeAndValue({
			type: "2.5.4.6", // Country name
			value: new PrintableString({ value: "RU" })
		}));
		certSimpl.subject.typesAndValues.push(new AttributeTypeAndValue({
			type: "2.5.4.3", // Common name
			value: new BmpString({ value: "Test" })
		}));

		certSimpl.notBefore.value = new Date(2016, 1, 1);
		certSimpl.notAfter.value = new Date(2019, 1, 1);

		certSimpl.extensions = []; // Extensions are not a part of certificate by default, it's an optional array

		//region "KeyUsage" extension
		var bitArray = new ArrayBuffer(1);
		var bitView = new Uint8Array(bitArray);

		bitView[0] = bitView[0] | 0x02; // Key usage "cRLSign" flag
		//bitView[0] = bitView[0] | 0x04; // Key usage "keyCertSign" flag

		var keyUsage = new BitString({ valueHex: bitArray });

		certSimpl.extensions.push(new Extension({
			extnID: "2.5.29.15",
			critical: false,
			extnValue: keyUsage.toBER(false),
			parsedValue: keyUsage // Parsed value for well-known extensions
		}));
		//endregion
		//endregion

		//region Create a new key pair
		sequence = sequence.then(function () {
			//region Get default algorithm parameters for key generation
			var algorithm = getAlgorithmParameters(signAlg, "generatekey");
			if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = hashAlg;
			//endregion

			return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
		});
		//endregion

		//region Store new key in an interim variables
		sequence = sequence.then(function (keyPair) {
			publicKey = keyPair.publicKey;
			privateKey = keyPair.privateKey;
		}, function (error) {
			return Promise.reject("Error during key generation: " + error);
		});
		//endregion

		//region Exporting public key into "subjectPublicKeyInfo" value of certificate
		sequence = sequence.then(function () {
			return certSimpl.subjectPublicKeyInfo.importKey(publicKey);
		});
		//endregion

		//region Signing final certificate
		sequence = sequence.then(function () {
			return certSimpl.sign(privateKey, hashAlg);
		}, function (error) {
			return Promise.reject("Error during exporting public key: " + error);
		});
		//endregion

		//region Encode and store certificate
		sequence = sequence.then(function () {
			trustedCertificates.push(certSimpl);
			certificateBuffer = certSimpl.toSchema(true).toBER(false);
		}, function (error) {
			return Promise.reject("Error during signing: " + error);
		});
		//endregion

		//region Exporting private key
		sequence = sequence.then(function () {
			return crypto.exportKey("pkcs8", privateKey);
		});
		//endregion

		//region Store exported key on Web page
		sequence = sequence.then(function (result) {
			privateKeyBuffer = result;
		}, function (error) {
			return Promise.reject("Error during exporting of private key: " + error);
		});
		//endregion*/

		//region Check if user wants us to include signed extensions
		if (addExt) {
			//region Create a message digest
			sequence = sequence.then(function () {
				return crypto.digest({ name: hashAlg }, new Uint8Array(dataBuffer));
			});
			//endregion

			//region Combine all signed extensions
			sequence = sequence.then(function (result) {
				var signedAttr = [];

				signedAttr.push(new Attribute({
					type: "1.2.840.113549.1.9.3",
					values: [new ObjectIdentifier({ value: "1.2.840.113549.1.7.1" })]
				})); // contentType

				signedAttr.push(new Attribute({
					type: "1.2.840.113549.1.9.5",
					values: [new UTCTime({ valueDate: new Date() })]
				})); // signingTime

				signedAttr.push(new Attribute({
					type: "1.2.840.113549.1.9.4",
					values: [new OctetString({ valueHex: result })]
				})); // messageDigest

				return signedAttr;
			});
			//endregion
		}
		//endregion

		//region Initialize CMS Signed Data structures and sign it
		sequence = sequence.then(function (result) {
			cmsSignedSimpl = new SignedData({
				version: 1,
				encapContentInfo: new EncapsulatedContentInfo({
					eContentType: "1.2.840.113549.1.7.1" // "data" content type
				}),
				signerInfos: [new SignerInfo({
					version: 1,
					sid: new IssuerAndSerialNumber({
						issuer: certSimpl.issuer,
						serialNumber: certSimpl.serialNumber
					})
				})],
				certificates: [certSimpl]
			});

			if (addExt) {
				cmsSignedSimpl.signerInfos[0].signedAttrs = new SignedAndUnsignedAttributes({
					type: 0,
					attributes: result
				});
			}

			if (detachedSignature === false) {
				var contentInfo = new EncapsulatedContentInfo({
					eContent: new OctetString({ valueHex: dataBuffer })
				});

				cmsSignedSimpl.encapContentInfo.eContent = contentInfo.eContent;

				return cmsSignedSimpl.sign(privateKey, 0, hashAlg);
			}

			return cmsSignedSimpl.sign(privateKey, 0, hashAlg, dataBuffer);
		});
		//endregion

		//region Create final result
		sequence.then(function () {
			var cmsSignedSchema = cmsSignedSimpl.toSchema(true);

			var cmsContentSimp = new ContentInfo({
				contentType: "1.2.840.113549.1.7.2",
				content: cmsSignedSchema
			});

			var _cmsSignedSchema = cmsContentSimp.toSchema(true);

			//region Make length of some elements in "indefinite form"
			_cmsSignedSchema.lenBlock.isIndefiniteForm = true;

			var block1 = _cmsSignedSchema.valueBlock.value[1];
			block1.lenBlock.isIndefiniteForm = true;

			var block2 = block1.valueBlock.value[0];
			block2.lenBlock.isIndefiniteForm = true;

			if (detachedSignature === false) {
				var block3 = block2.valueBlock.value[2];
				block3.lenBlock.isIndefiniteForm = true;
				block3.valueBlock.value[1].lenBlock.isIndefiniteForm = true;
				block3.valueBlock.value[1].valueBlock.value[0].lenBlock.isIndefiniteForm = true;
			}
			//endregion

			cmsSignedBuffer = _cmsSignedSchema.toBER(false);
		}, function (error) {
			return Promise.reject("Erorr during signing of CMS Signed Data: " + error);
		});
		//endregion

		return sequence;
	}
	//*********************************************************************************

	//**************************************************************************************
	/**
  * Class from RFC5280
  */

	var Certificate = function () {
		//**********************************************************************************
		/**
   * Constructor for Certificate class
   * @param {Object} [parameters={}]
   * @property {Object} [schema] asn1js parsed value
   */
		function Certificate() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			_classCallCheck(this, Certificate);

			//region Internal properties of the object
			/**
    * @type {ArrayBuffer}
    * @description tbs
    */
			this.tbs = getParametersValue(parameters, "tbs", Certificate.defaultValues("tbs"));
			/**
    * @type {number}
    * @description version
    */
			this.version = getParametersValue(parameters, "version", Certificate.defaultValues("version"));
			/**
    * @type {Integer}
    * @description serialNumber
    */
			this.serialNumber = getParametersValue(parameters, "serialNumber", Certificate.defaultValues("serialNumber"));
			/**
    * @type {AlgorithmIdentifier}
    * @description signature
    */
			this.signature = getParametersValue(parameters, "signature", Certificate.defaultValues("signature"));
			/**
    * @type {RelativeDistinguishedNames}
    * @description issuer
    */
			this.issuer = getParametersValue(parameters, "issuer", Certificate.defaultValues("issuer"));
			/**
    * @type {Time}
    * @description notBefore
    */
			this.notBefore = getParametersValue(parameters, "notBefore", Certificate.defaultValues("notBefore"));
			/**
    * @type {Time}
    * @description notAfter
    */
			this.notAfter = getParametersValue(parameters, "notAfter", Certificate.defaultValues("notAfter"));
			/**
    * @type {RelativeDistinguishedNames}
    * @description subject
    */
			this.subject = getParametersValue(parameters, "subject", Certificate.defaultValues("subject"));
			/**
    * @type {PublicKeyInfo}
    * @description subjectPublicKeyInfo
    */
			this.subjectPublicKeyInfo = getParametersValue(parameters, "subjectPublicKeyInfo", Certificate.defaultValues("subjectPublicKeyInfo"));

			if ("issuerUniqueID" in parameters)
				/**
     * @type {ArrayBuffer}
     * @description issuerUniqueID
     */
				this.issuerUniqueID = getParametersValue(parameters, "issuerUniqueID", Certificate.defaultValues("issuerUniqueID"));

			if ("subjectUniqueID" in parameters)
				/**
     * @type {ArrayBuffer}
     * @description subjectUniqueID
     */
				this.subjectUniqueID = getParametersValue(parameters, "subjectUniqueID", Certificate.defaultValues("subjectUniqueID"));

			if ("extensions" in parameters)
				/**
     * @type {Array}
     * @description extensions
     */
				this.extensions = getParametersValue(parameters, "extensions", Certificate.defaultValues("extensions"));

			/**
    * @type {AlgorithmIdentifier}
    * @description signatureAlgorithm
    */
			this.signatureAlgorithm = getParametersValue(parameters, "signatureAlgorithm", Certificate.defaultValues("signatureAlgorithm"));
			/**
    * @type {BitString}
    * @description signatureValue
    */
			this.signatureValue = getParametersValue(parameters, "signatureValue", Certificate.defaultValues("signatureValue"));
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


		_createClass(Certificate, [{
			key: "fromSchema",

			//**********************************************************************************
			/**
    * Convert parsed asn1js object into current class
    * @param {!Object} schema
    */
			value: function fromSchema(schema) {
				//region Check the schema is valid
				var asn1 = compareSchema(schema, schema, Certificate.schema({
					names: {
						tbsCertificate: {
							names: {
								extensions: {
									names: {
										extensions: "tbsCertificate.extensions"
									}
								}
							}
						}
					}
				}));

				if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CERT");
				//endregion

				//region Get internal properties from parsed schema
				this.tbs = asn1.result.tbsCertificate.valueBeforeDecode;

				if ("tbsCertificate.version" in asn1.result) this.version = asn1.result["tbsCertificate.version"].valueBlock.valueDec;
				this.serialNumber = asn1.result["tbsCertificate.serialNumber"];
				this.signature = new AlgorithmIdentifier({ schema: asn1.result["tbsCertificate.signature"] });
				this.issuer = new RelativeDistinguishedNames({ schema: asn1.result["tbsCertificate.issuer"] });
				this.notBefore = new Time({ schema: asn1.result["tbsCertificate.notBefore"] });
				this.notAfter = new Time({ schema: asn1.result["tbsCertificate.notAfter"] });
				this.subject = new RelativeDistinguishedNames({ schema: asn1.result["tbsCertificate.subject"] });
				this.subjectPublicKeyInfo = new PublicKeyInfo({ schema: asn1.result["tbsCertificate.subjectPublicKeyInfo"] });
				if ("tbsCertificate.issuerUniqueID" in asn1.result) this.issuerUniqueID = asn1.result["tbsCertificate.issuerUniqueID"].valueBlock.valueHex;
				if ("tbsCertificate.subjectUniqueID" in asn1.result) this.issuerUniqueID = asn1.result["tbsCertificate.subjectUniqueID"].valueBlock.valueHex;
				if ("tbsCertificate.extensions" in asn1.result) this.extensions = Array.from(asn1.result["tbsCertificate.extensions"], function (element) {
					return new Extension({ schema: element });
				});

				this.signatureAlgorithm = new AlgorithmIdentifier({ schema: asn1.result.signatureAlgorithm });
				this.signatureValue = asn1.result.signatureValue;
				//endregion
			}
			//**********************************************************************************
			/**
    * Create ASN.1 schema for existing values of TBS part for the certificate
    */

		}, {
			key: "encodeTBS",
			value: function encodeTBS() {
				//region Create array for output sequence
				var outputArray = [];

				if ("version" in this && this.version !== Certificate.defaultValues("version")) {
					outputArray.push(new Constructed({
						optional: true,
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						},
						value: [new Integer({ value: this.version }) // EXPLICIT integer value
						]
					}));
				}

				outputArray.push(this.serialNumber);
				outputArray.push(this.signature.toSchema());
				outputArray.push(this.issuer.toSchema());

				outputArray.push(new Sequence({
					value: [this.notBefore.toSchema(), this.notAfter.toSchema()]
				}));

				outputArray.push(this.subject.toSchema());
				outputArray.push(this.subjectPublicKeyInfo.toSchema());

				if ("issuerUniqueID" in this) {
					outputArray.push(new Primitive({
						optional: true,
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 1 // [1]
						},
						valueHex: this.issuerUniqueID
					}));
				}
				if ("subjectUniqueID" in this) {
					outputArray.push(new Primitive({
						optional: true,
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 2 // [2]
						},
						valueHex: this.subjectUniqueID
					}));
				}

				if ("subjectUniqueID" in this) {
					outputArray.push(new Primitive({
						optional: true,
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 3 // [3]
						},
						value: [this.extensions.toSchema()]
					}));
				}

				if ("extensions" in this) {
					outputArray.push(new Constructed({
						optional: true,
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 3 // [3]
						},
						value: [new Sequence({
							value: Array.from(this.extensions, function (element) {
								return element.toSchema();
							})
						})]
					}));
				}
				//endregion

				//region Create and return output sequence
				return new Sequence({
					value: outputArray
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
				var encodeFlag = arguments.length <= 0 || arguments[0] === undefined ? false : arguments[0];

				var tbsSchema = {};

				//region Decode stored TBS value
				if (encodeFlag === false) {
					if (this.tbs.length === 0) // No stored certificate TBS part
						return Certificate.schema().value[0];

					tbsSchema = fromBER(this.tbs).result;
				}
				//endregion
				//region Create TBS schema via assembling from TBS parts
				else tbsSchema = this.encodeTBS();
				//endregion

				//region Construct and return new ASN.1 schema for this object
				return new Sequence({
					value: [tbsSchema, this.signatureAlgorithm.toSchema(), this.signatureValue]
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
					tbs: bufferToHexCodes(this.tbs, 0, this.tbs.byteLength),
					serialNumber: this.serialNumber.toJSON(),
					signature: this.signature.toJSON(),
					issuer: this.issuer.toJSON(),
					notBefore: this.notBefore.toJSON(),
					notAfter: this.notAfter.toJSON(),
					subject: this.subject.toJSON(),
					subjectPublicKeyInfo: this.subjectPublicKeyInfo.toJSON(),
					signatureAlgorithm: this.signatureAlgorithm.toJSON(),
					signatureValue: this.signatureValue.toJSON()
				};

				if ("version" in this && this.version !== Certificate.defaultValues("version")) object.version = this.version;

				if ("issuerUniqueID" in this) object.issuerUniqueID = bufferToHexCodes(this.issuerUniqueID, 0, this.issuerUniqueID.byteLength);

				if ("subjectUniqueID" in this) object.subjectUniqueID = bufferToHexCodes(this.subjectUniqueID, 0, this.subjectUniqueID.byteLength);

				if ("extensions" in this) object.extensions = Array.from(this.extensions, function (element) {
					return element.toJSON();
				});

				return object;
			}
			//**********************************************************************************
			/**
    * Importing public key for current certificate
    */

		}, {
			key: "getPublicKey",
			value: function getPublicKey() {
				var parameters = arguments.length <= 0 || arguments[0] === undefined ? null : arguments[0];

				//region Get a "crypto" extension
				var crypto = getCrypto();
				if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
				//endregion

				//region Find correct algorithm for imported public key
				if (parameters === null) {
					//region Initial variables
					parameters = {};
					//endregion

					//region Find signer's hashing algorithm
					var shaAlgorithm = getHashAlgorithm(this.signatureAlgorithm);
					if (shaAlgorithm === "") return Promise.reject("Unsupported signature algorithm: " + this.signatureAlgorithm.algorithmId);
					//endregion

					//region Get information about public key algorithm and default parameters for import
					var algorithmObject = getAlgorithmByOID(this.subjectPublicKeyInfo.algorithm.algorithmId);
					if ("name" in algorithmObject === false) return Promise.reject("Unsupported public key algorithm: " + this.subjectPublicKeyInfo.algorithm.algorithmId);

					parameters.algorithm = getAlgorithmParameters(algorithmObject.name, "importkey");
					if ("hash" in parameters.algorithm.algorithm) parameters.algorithm.algorithm.hash.name = shaAlgorithm;

					//region Special case for ECDSA
					if (algorithmObject.name === "ECDSA") {
						//region Get information about named curve
						var algorithmParamsChecked = false;

						if ("algorithmParams" in this.subjectPublicKeyInfo.algorithm === true) {
							if ("idBlock" in this.subjectPublicKeyInfo.algorithm.algorithmParams) {
								if (this.subjectPublicKeyInfo.algorithm.algorithmParams.idBlock.tagClass === 1 && this.subjectPublicKeyInfo.algorithm.algorithmParams.idBlock.tagNumber === 6) algorithmParamsChecked = true;
							}
						}

						if (algorithmParamsChecked === false) return Promise.reject("Incorrect type for ECDSA public key parameters");

						var curveObject = getAlgorithmByOID(this.subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
						if ("name" in curveObject === false) return Promise.reject("Unsupported named curve algorithm: " + this.subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
						//endregion

						parameters.algorithm.algorithm.namedCurve = curveObject.name;
					}
					//endregion
					//endregion
				}
				//endregion

				//region Get neccessary values from internal fields for current certificate
				var publicKeyInfoSchema = this.subjectPublicKeyInfo.toSchema();
				var publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);
				var publicKeyInfoView = new Uint8Array(publicKeyInfoBuffer);
				//endregion

				return crypto.importKey("spki", publicKeyInfoView, parameters.algorithm.algorithm, true, parameters.algorithm.usages);
			}
			//**********************************************************************************
			/**
    * Get SHA-1 hash value for subject public key
    */

		}, {
			key: "getKeyHash",
			value: function getKeyHash() {
				//region Get a "crypto" extension
				var crypto = getCrypto();
				if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
				//endregion

				return crypto.digest({ name: "sha-1" }, new Uint8Array(this.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex));
			}
			//**********************************************************************************
			/**
    * Make a signature for current value from TBS section
    * @param {Object} privateKey Private key for "subjectPublicKeyInfo" structure
    * @param {string} [hashAlgorithm="SHA-1"] Hashing algorithm
    */

		}, {
			key: "sign",
			value: function sign(privateKey) {
				var _this54 = this;

				var hashAlgorithm = arguments.length <= 1 || arguments[1] === undefined ? "SHA-1" : arguments[1];

				//region Get hashing algorithm
				var oid = getOIDByAlgorithm({ name: hashAlgorithm });
				if (oid === "") return Promise.reject("Unsupported hash algorithm: " + hashAlgorithm);
				//endregion

				//region Get a "default parameters" for current algorithm
				var defParams = getAlgorithmParameters(privateKey.algorithm.name, "sign");
				defParams.algorithm.hash.name = hashAlgorithm;
				//endregion

				//region Fill internal structures base on "privateKey" and "hashAlgorithm"
				switch (privateKey.algorithm.name.toUpperCase()) {
					case "RSASSA-PKCS1-V1_5":
					case "ECDSA":
						this.signature.algorithmId = getOIDByAlgorithm(defParams.algorithm);
						this.signatureAlgorithm.algorithmId = this.signature.algorithmId;
						break;
					case "RSA-PSS":
						{
							//region Set "saltLength" as a length (in octets) of hash function result
							switch (hashAlgorithm.toUpperCase()) {
								case "SHA-256":
									defParams.algorithm.saltLength = 32;
									break;
								case "SHA-384":
									defParams.algorithm.saltLength = 48;
									break;
								case "SHA-512":
									defParams.algorithm.saltLength = 64;
									break;
								default:
							}
							//endregion

							//region Fill "RSASSA_PSS_params" object
							var paramsObject = {};

							if (hashAlgorithm.toUpperCase() !== "SHA-1") {
								var hashAlgorithmOID = getOIDByAlgorithm({ name: hashAlgorithm });
								if (hashAlgorithmOID === "") return Promise.reject("Unsupported hash algorithm: " + hashAlgorithm);

								paramsObject.hashAlgorithm = new AlgorithmIdentifier({
									algorithmId: hashAlgorithmOID,
									algorithmParams: new Null()
								});

								paramsObject.maskGenAlgorithm = new AlgorithmIdentifier({
									algorithmId: "1.2.840.113549.1.1.8", // MGF1
									algorithmParams: paramsObject.hashAlgorithm.toSchema()
								});
							}

							if (defParams.algorithm.saltLength !== 20) paramsObject.saltLength = defParams.algorithm.saltLength;

							var pssParameters = new RSASSAPSSParams(paramsObject);
							//endregion

							//region Automatically set signature algorithm
							this.signature = new AlgorithmIdentifier({
								algorithmId: "1.2.840.113549.1.1.10",
								algorithmParams: pssParameters.toSchema()
							});
							this.signatureAlgorithm = this.signature; // Must be the same
							//endregion
						}
						break;
					default:
						return Promise.reject("Unsupported signature algorithm: " + privateKey.algorithm.name);
				}
				//endregion

				//region Create TBS data for signing
				this.tbs = this.encodeTBS().toBER(false);
				//endregion

				//region Get a "crypto" extension
				var crypto = getCrypto();
				if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
				//endregion

				//region Signing TBS data on provided private key
				return crypto.sign(defParams.algorithm, privateKey, new Uint8Array(this.tbs)).then(function (result) {
					//region Special case for ECDSA algorithm
					if (defParams.algorithm.name === "ECDSA") result = createCMSECDSASignature(result);
					//endregion

					_this54.signatureValue = new BitString({ valueHex: result });
				}, function (error) {
					return Promise.reject("Signing error: " + error);
				});
				//endregion
			}
			//**********************************************************************************

		}, {
			key: "verify",
			value: function verify() {
				var _this55 = this;

				var issuerCertificate = arguments.length <= 0 || arguments[0] === undefined ? null : arguments[0];

				//region Global variables
				var sequence = Promise.resolve();

				var subjectPublicKeyInfo = {};

				var signature = this.signatureValue;
				var tbs = this.tbs;
				//endregion

				//region Set correct "subjectPublicKeyInfo" value
				if (issuerCertificate !== null) subjectPublicKeyInfo = issuerCertificate.subjectPublicKeyInfo;else {
					if (this.issuer.isEqual(this.subject)) // Self-signed certificate
						subjectPublicKeyInfo = this.subjectPublicKeyInfo;
				}

				if (subjectPublicKeyInfo instanceof PublicKeyInfo === false) return Promise.reject("Please provide issuer certificate as a parameter");
				//endregion

				//region Get a "crypto" extension
				var crypto = getCrypto();
				if (typeof crypto === "undefined") return Promise.reject("Unable to create WebCrypto object");
				//endregion

				//region Find signer's hashing algorithm
				var shaAlgorithm = getHashAlgorithm(this.signatureAlgorithm);
				if (shaAlgorithm === "") return Promise.reject("Unsupported signature algorithm: " + this.signatureAlgorithm.algorithmId);
				//endregion

				//region Importing public key
				sequence = sequence.then(function () {
					//region Get information about public key algorithm and default parameters for import
					var algorithmId = void 0;
					if (_this55.signatureAlgorithm.algorithmId === "1.2.840.113549.1.1.10") algorithmId = _this55.signatureAlgorithm.algorithmId;else algorithmId = subjectPublicKeyInfo.algorithm.algorithmId;

					var algorithmObject = getAlgorithmByOID(algorithmId);
					if ("name" in algorithmObject === false) return Promise.reject("Unsupported public key algorithm: " + algorithmId);

					var algorithm = getAlgorithmParameters(algorithmObject.name, "importkey");
					if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;

					//region Special case for ECDSA
					if (algorithmObject.name === "ECDSA") {
						// #region Get information about named curve
						var algorithmParamsChecked = false;

						if ("algorithmParams" in subjectPublicKeyInfo.algorithm === true) {
							if ("idBlock" in subjectPublicKeyInfo.algorithm.algorithmParams) {
								if (subjectPublicKeyInfo.algorithm.algorithmParams.idBlock.tagClass === 1 && subjectPublicKeyInfo.algorithm.algorithmParams.idBlock.tagNumber === 6) algorithmParamsChecked = true;
							}
						}

						if (algorithmParamsChecked === false) return Promise.reject("Incorrect type for ECDSA public key parameters");

						var curveObject = getAlgorithmByOID(subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
						if ("name" in curveObject === false) return Promise.reject("Unsupported named curve algorithm: " + subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
						// #endregion

						algorithm.algorithm.namedCurve = curveObject.name;
					}
					//endregion
					//endregion

					var publicKeyInfoSchema = subjectPublicKeyInfo.toSchema();
					var publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);
					var publicKeyInfoView = new Uint8Array(publicKeyInfoBuffer);

					return crypto.importKey("spki", publicKeyInfoView, algorithm.algorithm, true, algorithm.usages);
				});
				//endregion

				//region Verify signature for the certificate
				sequence = sequence.then(function (publicKey) {
					//region Get default algorithm parameters for verification
					var algorithm = getAlgorithmParameters(publicKey.algorithm.name, "verify");
					if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;
					//endregion

					//region Special case for ECDSA signatures
					var signatureValue = signature.valueBlock.valueHex;

					if (publicKey.algorithm.name === "ECDSA") {
						var asn1 = fromBER(signatureValue);
						signatureValue = createECDSASignatureFromCMS(asn1.result);
					}
					//endregion

					//region Special case for RSA-PSS
					if (publicKey.algorithm.name === "RSA-PSS") {
						var pssParameters = void 0;

						try {
							pssParameters = new RSASSAPSSParams({ schema: _this55.signatureAlgorithm.algorithmParams });
						} catch (ex) {
							return Promise.reject(ex);
						}

						if ("saltLength" in pssParameters) algorithm.algorithm.saltLength = pssParameters.saltLength;else algorithm.algorithm.saltLength = 20;

						var hashAlgo = "SHA-1";

						if ("hashAlgorithm" in pssParameters) {
							var hashAlgorithm = getAlgorithmByOID(pssParameters.hashAlgorithm.algorithmId);
							if ("name" in hashAlgorithm === false) return Promise.reject("Unrecognized hash algorithm: " + pssParameters.hashAlgorithm.algorithmId);

							hashAlgo = hashAlgorithm.name;
						}

						algorithm.algorithm.hash.name = hashAlgo;
					}
					//endregion

					return crypto.verify(algorithm.algorithm, publicKey, new Uint8Array(signatureValue), new Uint8Array(tbs));
				});
				//endregion

				return sequence;
			}
			//**********************************************************************************
			//region Basic Building Blocks for Verification Engine
			//**********************************************************************************

		}, {
			key: "formatChecking",
			value: function formatChecking(_ref) {
				var _ref$strictChecking = _ref.strictChecking;
				var strictChecking = _ref$strictChecking === undefined ? false : _ref$strictChecking;

				if (strictChecking) {
					//region Check "version"
					if ("extensions" in this) {
						if (this.version !== 2) {
							return {
								indication: FAILED,
								message: "Version value for Certificate must be 2 (V3)"
							};
						}
					} else {
						if ("subjectUniqueID" in this || "issuerUniqueID" in this) {
							if (this.version !== 1 && this.version !== 2) {
								return {
									indication: FAILED,
									message: "Version value for Certificate must be 1 (V2) or 2 (V3)"
								};
							}
						} else {
							if (this.version !== 0) {
								return {
									indication: FAILED,
									message: "Version value for Certificate must be 0 (V1)"
								};
							}
						}
					}
					//endregion

					//region Check serial number
					var serialNumberView = new Uint8Array(this.serialNumber.valueBlock.valueHex);

					if ((serialNumberView[0] & 0x80) === 0x80) {
						return {
							indication: FAILED,
							message: "Serial number for Certificate must be encoded as non-negative integer"
						};
					}
					//endregion
				}

				//region Check all certificate's algorithms
				var algorithms = [this.signature.algorithmId, this.subjectPublicKeyInfo.algorithm.algorithmId, this.signatureAlgorithm.algorithmId];

				var algorithmsChecking = checkOids$1(algorithms);
				if (algorithmsChecking.indication !== PASSED) {
					return {
						indication: FAILED,
						message: "Incorrect OID in Certificate: " + algorithms[algorithmsCheckResult.message]
					};
				}
				//endregion

				//region Check validity period
				if (this.notBefore.value >= this.notAfter.value) {
					return {
						indication: FAILED,
						message: "Invalid validity perion for Certificate"
					};
				}
				//endregion

				return {
					indication: PASSED
				};
			}
			//**********************************************************************************

		}, {
			key: "cryptographicVerification",
			value: function cryptographicVerification(_ref2) {
				var _this56 = this;

				var _ref2$issuerCertifica = _ref2.issuerCertificate;
				var issuerCertificate = _ref2$issuerCertifica === undefined ? null : _ref2$issuerCertifica;

				//region Initial variables
				var sequence = Promise.resolve();

				var subjectPublicKeyInfo = {};

				var signature = this.signatureValue;
				var tbs = this.tbs;
				//endregion

				//region Set correct "subjectPublicKeyInfo" value
				if (issuerCertificate !== null) subjectPublicKeyInfo = issuerCertificate.subjectPublicKeyInfo;else {
					if (this.issuer.isEqual(this.subject)) // Self-signed certificate
						subjectPublicKeyInfo = this.subjectPublicKeyInfo;
				}

				if ("algorithm" in subjectPublicKeyInfo === false) {
					return Promise.resolve({
						indication: FAILED,
						subIndication: SIG_CRYPTO_FAILURE,
						message: "Please provide issuer certificate as a parameter"
					});
				}
				//endregion

				//region Get a "crypto" extension
				var crypto = getCrypto();
				if (typeof crypto === "undefined") {
					return Promise.resolve({
						indication: FAILED,
						subIndication: SIG_CRYPTO_FAILURE,
						message: "Unable to create WebCrypto object"
					});
				}
				//endregion

				//region Find signer's hashing algorithm
				var shaAlgorithm = getHashAlgorithm(this.signatureAlgorithm);
				if (shaAlgorithm === "") {
					return Promise.resolve({
						indication: FAILED,
						subIndication: SIG_CRYPTO_FAILURE,
						message: "Please run FormatChecking block before CryptographicVerification block: Unsupported signature algorithm: " + this.signatureAlgorithm.algorithmId
					});
				}
				//endregion

				//region Importing public key
				sequence = sequence.then(function () {
					//region Get information about public key algorithm and default parameters for import
					var algorithmId = void 0;
					if (_this56.signatureAlgorithm.algorithmId === "1.2.840.113549.1.1.10") algorithmId = _this56.signatureAlgorithm.algorithmId;else algorithmId = subjectPublicKeyInfo.algorithm.algorithmId;

					var algorithmObject = getAlgorithmByOID(algorithmId);
					if ("name" in algorithmObject === false) {
						return Promise.resolve({
							indication: FAILED,
							subIndication: SIG_CRYPTO_FAILURE,
							message: "Please run FormatChecking block before CryptographicVerification block: Unsupported public key algorithm: " + algorithmId
						});
					}

					var algorithm = getAlgorithmParameters(algorithmObject.name, "importkey");
					if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;

					//region Special case for ECDSA
					if (algorithmObject.name === "ECDSA") {
						// #region Get information about named curve
						var algorithmParamsChecked = false;

						if ("algorithmParams" in subjectPublicKeyInfo.algorithm === true) {
							if ("idBlock" in subjectPublicKeyInfo.algorithm.algorithmParams) {
								if (subjectPublicKeyInfo.algorithm.algorithmParams.idBlock.tagClass === 1 && subjectPublicKeyInfo.algorithm.algorithmParams.idBlock.tagNumber === 6) algorithmParamsChecked = true;
							}
						}

						if (algorithmParamsChecked === false) {
							return Promise.resolve({
								indication: FAILED,
								subIndication: SIG_CRYPTO_FAILURE,
								message: "Incorrect type for ECDSA public key parameters"
							});
						}

						var curveObject = getAlgorithmByOID(subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString());
						if ("name" in curveObject === false) {
							return Promise.resolve({
								indication: FAILED,
								subIndication: SIG_CRYPTO_FAILURE,
								message: "Unsupported named curve algorithm: " + subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString()
							});
						}
						// #endregion

						algorithm.algorithm.namedCurve = curveObject.name;
					}
					//endregion
					//endregion

					var publicKeyInfoSchema = subjectPublicKeyInfo.toSchema();
					var publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);
					var publicKeyInfoView = new Uint8Array(publicKeyInfoBuffer);

					return crypto.importKey("spki", publicKeyInfoView, algorithm.algorithm, true, algorithm.usages);
				});
				//endregion

				//region Verify signature for the certificate
				sequence = sequence.then(function (publicKey) {
					//region Get default algorithm parameters for verification
					var algorithm = getAlgorithmParameters(publicKey.algorithm.name, "verify");
					if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = shaAlgorithm;
					//endregion

					//region Special case for ECDSA signatures
					var signatureValue = signature.valueBlock.valueHex;

					if (publicKey.algorithm.name === "ECDSA") {
						var asn1 = fromBER(signatureValue);
						signatureValue = createECDSASignatureFromCMS(asn1.result);
					}
					//endregion

					//region Special case for RSA-PSS
					if (publicKey.algorithm.name === "RSA-PSS") {
						var pssParameters = void 0;

						try {
							pssParameters = new RSASSAPSSParams({ schema: _this56.signatureAlgorithm.algorithmParams });
						} catch (ex) {
							return Promise.reject(ex);
						}

						if ("saltLength" in pssParameters) algorithm.algorithm.saltLength = pssParameters.saltLength;else algorithm.algorithm.saltLength = 20;

						var hashAlgo = "SHA-1";

						if ("hashAlgorithm" in pssParameters) {
							var hashAlgorithm = getAlgorithmByOID(pssParameters.hashAlgorithm.algorithmId);
							if ("name" in hashAlgorithm === false) {
								return Promise.resolve({
									indication: FAILED,
									subIndication: SIG_CRYPTO_FAILURE,
									message: "Please run FormatChecking block before CryptographicVerification block: Unrecognized hash algorithm: " + pssParameters.hashAlgorithm.algorithmId
								});
							}

							hashAlgo = hashAlgorithm.name;
						}

						algorithm.algorithm.hash.name = hashAlgo;
					}
					//endregion

					return crypto.verify(algorithm.algorithm, publicKey, new Uint8Array(signatureValue), new Uint8Array(tbs));
				});
				//endregion

				//region Error handling stub
				sequence = sequence.then(function (result) {
					if (result) {
						return {
							indication: PASSED
						};
					}

					return {
						indication: FAILED,
						subIndication: SIG_CRYPTO_FAILURE,
						message: "Certificate signature was not verified"
					};
				}, function (error) {
					return Promise.resolve({
						indication: FAILED,
						subIndication: SIG_CRYPTO_FAILURE,
						message: "Error during process \"Certificate.cryptographicVerification\": " + error
					});
				});
				//endregion

				return sequence;
			}
			//**********************************************************************************
			//endregion
			//**********************************************************************************

		}], [{
			key: "defaultValues",
			value: function defaultValues(memberName) {
				switch (memberName) {
					case "tbs":
						return new ArrayBuffer(0);
					case "version":
						return 0;
					case "serialNumber":
						return new Integer();
					case "signature":
						return new AlgorithmIdentifier();
					case "issuer":
						return new RelativeDistinguishedNames();
					case "notBefore":
						return new Time();
					case "notAfter":
						return new Time();
					case "subject":
						return new RelativeDistinguishedNames();
					case "subjectPublicKeyInfo":
						return new PublicKeyInfo();
					case "issuerUniqueID":
						return new ArrayBuffer(0);
					case "subjectUniqueID":
						return new ArrayBuffer(0);
					case "extensions":
						return [];
					case "signatureAlgorithm":
						return new AlgorithmIdentifier();
					case "signatureValue":
						return new BitString();
					default:
						throw new Error("Invalid member name for Certificate class: " + memberName);
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

				//Certificate  ::=  SEQUENCE  {
				//    tbsCertificate       TBSCertificate,
				//    signatureAlgorithm   AlgorithmIdentifier,
				//    signatureValue       BIT STRING  }

				/**
     * @type {Object}
     * @property {string} [blockName]
     * @property {string} [tbsCertificate]
     * @property {string} [signatureAlgorithm]
     * @property {string} [signatureValue]
     */
				var names = getParametersValue(parameters, "names", {});

				return new Sequence({
					name: names.blockName || "",
					value: [tbsCertificate(names.tbsCertificate), AlgorithmIdentifier.schema(names.signatureAlgorithm || {
						names: {
							blockName: "signatureAlgorithm"
						}
					}), new BitString({ name: names.signatureValue || "signatureValue" })]
				});
			}
		}]);

		return Certificate;
	}();
	//**************************************************************************************