window.onload = function(){
		document.getElementById('create').onclick = function(){
			changeColor('red');
		}
		document.getElementById('smimeEncrypt').onclick = function(){
			changeColor('blue');
		}
		document.getElementById('smimeDecrypt').onclick = function(){
			changeColor('green');
		}

	}

	function changeColor(color){
		/*chrome.tabs.executeScript(null, 
			{"code":"document.body.style.backgroundColor='"+color+"'"}
		);*/
		if (color == 'red') {
			createCertificate();
		} else if (color == 'blue') {
			smimeEncrypt();
		} else if (color == 'green') {
			smimeDecrypt();
		};
	}

	function createCertificate() {
		//region Initial variables
		var sequence = Promise.resolve();

		var certificate = new Certificate();

		var publicKey = void 0;
		var privateKey = void 0;
		//endregion

		//region Get a "crypto" extension
		var crypto = getCrypto();
		if (typeof crypto === "undefined") {
			alert("No WebCrypto extension found");
			return;
		}
		//endregion

		//region Put a static values
		certificate.version = 2;
		certificate.serialNumber = new Integer({ value: 1 });
		certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
			type: "2.5.4.6", // Country name
			value: new PrintableString({ value: "RU" })
		}));
		certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
			type: "2.5.4.3", // Common name
			value: new BmpString({ value: "Test" })
		}));
		certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
			type: "2.5.4.6", // Country name
			value: new PrintableString({ value: "RU" })
		}));
		certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
			type: "2.5.4.3", // Common name
			value: new BmpString({ value: "Test" })
		}));

		certificate.notBefore.value = new Date(2016, 1, 1);
		certificate.notAfter.value = new Date(2019, 1, 1);

		certificate.extensions = []; // Extensions are not a part of certificate by default, it"s an optional array

		//region "BasicConstraints" extension
		var basicConstr = new BasicConstraints({
			cA: true,
			pathLenConstraint: 3
		});

		certificate.extensions.push(new Extension({
			extnID: "2.5.29.19",
			critical: false,
			extnValue: basicConstr.toSchema().toBER(false),
			parsedValue: basicConstr // Parsed value for well-known extensions
		}));
		//endregion

		//region "KeyUsage" extension
		var bitArray = new ArrayBuffer(1);
		var bitView = new Uint8Array(bitArray);

		bitView[0] = bitView[0] | 0x02; // Key usage "cRLSign" flag
		bitView[0] = bitView[0] | 0x04; // Key usage "keyCertSign" flag

		var keyUsage = new BitString({ valueHex: bitArray });

		certificate.extensions.push(new Extension({
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
			alert("Error during key generation: " + error);
		});
		//endregion

		//region Exporting public key into "subjectPublicKeyInfo" value of certificate
		sequence = sequence.then(function () {
			return certificate.subjectPublicKeyInfo.importKey(publicKey);
		});
		//endregion

		//region Signing final certificate
		sequence = sequence.then(function () {
			return certificate.sign(privateKey, hashAlg);
		}, function (error) {
			alert("Error during exporting public key: " + error);
		});
		//endregion

		//region Encode and store certificate
		sequence = sequence.then(function () {
			certificateBuffer = certificate.toSchema(true).toBER(false);

			var certificateString = String.fromCharCode.apply(null, new Uint8Array(certificateBuffer));

			var resultString = "-----BEGIN CERTIFICATE-----\r\n";
			resultString = "" + resultString + formatPEM(window.btoa(certificateString));
			resultString = resultString + "\r\n-----END CERTIFICATE-----\r\n";

			trustedCertificates.push(certificate);

			document.getElementById("new_signed_data").innerHTML = resultString;

			alert("Certificate created successfully!");
		}, function (error) {
			alert("Error during signing: " + error);
		});
		//endregion

		//region Exporting private key
		sequence = sequence.then(function () {
			return crypto.exportKey("pkcs8", privateKey);
		});
		//endregion

		//region Store exported key on Web page
		sequence = sequence.then(function (result) {
			var privateKeyString = String.fromCharCode.apply(null, new Uint8Array(result));

			var resultString = "";

			resultString = resultString + "\r\n-----BEGIN PRIVATE KEY-----\r\n";
			resultString = "" + resultString + formatPEM(window.btoa(privateKeyString));
			resultString = resultString + "\r\n-----END PRIVATE KEY-----\r\n";

			document.getElementById("pkcs8_key").innerHTML = resultString;

			alert("Private key exported successfully!");
		}, function (error) {
			alert("Error during exporting of private key: " + error);
		});
		//endregion

		return sequence;
	}

		var CertificatePolicies = function () {
		//**********************************************************************************
		/**
   * Constructor for CertificatePolicies class
   * @param {Object} [parameters={}]
   * @property {Object} [schema] asn1js parsed value
   */
		function CertificatePolicies() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			_classCallCheck(this, CertificatePolicies);

			//region Internal properties of the object
			/**
    * @type {Array.<PolicyInformation>}
    * @description certificatePolicies
    */
			this.certificatePolicies = getParametersValue(parameters, "certificatePolicies", CertificatePolicies.defaultValues("certificatePolicies"));
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


		_createClass(CertificatePolicies, [{
			key: "fromSchema",

			//**********************************************************************************
			/**
    * Convert parsed asn1js object into current class
    * @param {!Object} schema
    */
			value: function fromSchema(schema) {
				//region Check the schema is valid
				var asn1 = compareSchema(schema, schema, CertificatePolicies.schema({
					names: {
						certificatePolicies: "certificatePolicies"
					}
				}));

				if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CertificatePolicies");
				//endregion

				//region Get internal properties from parsed schema
				this.certificatePolicies = Array.from(asn1.result.certificatePolicies, function (element) {
					return new PolicyInformation({ schema: element });
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
				//region Construct and return new ASN.1 schema for this object
				return new Sequence({
					value: Array.from(this.certificatePolicies, function (element) {
						return element.toSchema();
					})
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
				return {
					certificatePolicies: Array.from(this.certificatePolicies, function (element) {
						return element.toJSON();
					})
				};
			}
			//**********************************************************************************

		}], [{
			key: "defaultValues",
			value: function defaultValues(memberName) {
				switch (memberName) {
					case "certificatePolicies":
						return [];
					default:
						throw new Error("Invalid member name for CertificatePolicies class: " + memberName);
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

				// CertificatePolicies OID ::= 2.5.29.32
				//
				//certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

				/**
     * @type {Object}
     * @property {string} [blockName]
     * @property {string} [certificatePolicies]
     */
				var names = getParametersValue(parameters, "names", {});

				return new Sequence({
					name: names.blockName || "",
					value: [new Repeated({
						name: names.certificatePolicies || "",
						value: PolicyInformation.schema()
					})]
				});
			}
		}]);

		return CertificatePolicies;
	}();

	function smimeEncrypt() {
		//region Decode input certificate 
		var encodedCertificate = document.getElementById("new_signed_data").innerHTML;
		var clearEncodedCertificate = encodedCertificate.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, "");
		certificateBuffer = stringToArrayBuffer(window.atob(clearEncodedCertificate));

		var asn1 = fromBER(certificateBuffer);
		var certSimpl = new Certificate({ schema: asn1.result });
		//endregion 

		var cmsEnveloped = new EnvelopedData();

		cmsEnveloped.addRecipientByCertificate(certSimpl);

		cmsEnveloped.encrypt(encAlg, stringToArrayBuffer(document.getElementById("content").value)).then(function () {
			var cmsContentSimpl = new ContentInfo();
			cmsContentSimpl.contentType = "1.2.840.113549.1.7.3";
			cmsContentSimpl.content = cmsEnveloped.toSchema();

			var schema = cmsContentSimpl.toSchema();
			var ber = schema.toBER(false);

			// Insert enveloped data into new Mime message
			var Mimebuilder = window["emailjs-mime-builder"];
			var mimeBuilder = new Mimebuilder("application/pkcs7-mime; name=smime.p7m; smime-type=enveloped-data").setHeader("content-description", "Enveloped Data").setHeader("content-disposition", "attachment; filename=smime.p7m").setHeader("content-transfer-encoding", "base64").setContent(new Uint8Array(ber));
			mimeBuilder.setHeader("from", "sender@example.com");
			mimeBuilder.setHeader("to", "recipient@example.com");
			mimeBuilder.setHeader("subject", "Example S/MIME encrypted message");
			var mimeMessage = mimeBuilder.build();

			document.getElementById("encrypted_content").innerHTML = mimeMessage;

			alert("Encryption process finished successfully");
		}, function (error) {
			return alert("ERROR DURING ENCRYPTION PROCESS: " + error);
		});
	}
	//*********************************************************************************
	//endregion 
	//*********************************************************************************
	//region Decrypt input data 
	//*********************************************************************************
	function smimeDecrypt() {
		//region Decode input certificate 
		var encodedCertificate = document.getElementById("new_signed_data").innerHTML;
		var clearEncodedCertificate = encodedCertificate.replace(/(-----(BEGIN|END)( NEW)? CERTIFICATE-----|\n)/g, "");
		certificateBuffer = stringToArrayBuffer(window.atob(clearEncodedCertificate));

		var asn1 = fromBER(certificateBuffer);
		var certSimpl = new Certificate({ schema: asn1.result });
		//endregion 

		//region Decode input private key 
		var encodedPrivateKey = document.getElementById("pkcs8_key").innerHTML;
		var clearPrivateKey = encodedPrivateKey.replace(/(-----(BEGIN|END)( NEW)? PRIVATE KEY-----|\n)/g, "");
		var privateKeyBuffer = stringToArrayBuffer(window.atob(clearPrivateKey));
		//endregion 

		//region Parse S/MIME message to get CMS enveloped content 

		// Parse MIME message and extract the envelope data
		var parser = new MimeParser();

		var mimeMessage = document.getElementById("encrypted_content").innerHTML;
		parser.write(mimeMessage);
		parser.end();
		//endregion

		// Note: MimeParser handles the base64 decoding to get us back a buffer
		var cmsEnvelopedBuffer = utilConcatBuf(new ArrayBuffer(0), parser.node.content);

		asn1 = fromBER(cmsEnvelopedBuffer);
		var cmsContentSimpl = new ContentInfo({ schema: asn1.result });
		var cmsEnvelopedSimp = new EnvelopedData({ schema: cmsContentSimpl.content });
		//endregion 

		cmsEnvelopedSimp.decrypt(0, {
			recipientCertificate: certSimpl,
			recipientPrivateKey: privateKeyBuffer
		}).then(function (result) {
			document.getElementById("decrypted_content").innerHTML = arrayBufferToString(result);
		}, function (error) {
			return alert("ERROR DURING DECRYPTION PROCESS: " + error);
		});
	}
