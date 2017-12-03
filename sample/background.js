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
		return createCMSSignedInternal().then(function () {
			var certSimplString = String.fromCharCode.apply(null, new Uint8Array(certificateBuffer));

			var resultString = "-----BEGIN CERTIFICATE-----\r\n";
			resultString = resultString + formatPEM(window.btoa(certSimplString));
			resultString = resultString + "\r\n-----END CERTIFICATE-----\r\n";

			alert("Certificate created successfully!");

			var privateKeyString = String.fromCharCode.apply(null, new Uint8Array(privateKeyBuffer));

			resultString = resultString + "\r\n-----BEGIN PRIVATE KEY-----\r\n";
			resultString = resultString + formatPEM(window.btoa(privateKeyString));
			resultString = resultString + "\r\n-----END PRIVATE KEY-----\r\n";

			document.getElementById("new_signed_data").innerHTML = resultString;

			alert("Private key exported successfully!");

			var signedDataString = String.fromCharCode.apply(null, new Uint8Array(cmsSignedBuffer));


			resultString = resultString + "\r\n-----BEGIN CMS-----\r\n";
			resultString = resultString + formatPEM(window.btoa(signedDataString));
			resultString = resultString + "\r\n-----END CMS-----\r\n\r\n";

			document.getElementById("new_signed_data").innerHTML = resultString;

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
		//region Initial variables
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
		//endregion

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