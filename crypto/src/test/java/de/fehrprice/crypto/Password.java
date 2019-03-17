package de.fehrprice.crypto;

import java.math.BigInteger;

import de.fehrprice.crypto.RSA;

public class Password {

// generated on previous run:	
//public key  (used to encrypt): d262c5e4931ecf89bc8148aefed71cca888928b419bc925c993247f78104cf7f285693df89a4ddf7c3d067afabac89a5f1dedc4056ff959868a4a382fa211f4b29378ffb62cba0fdacd8aec3b41b9100ce4ca90b229c763d5b4f6a911403d767b0d2c0de5a988cc408a4a911f2519f5dc4962cba4bc9e254ce94d38996af83b1251aeda1e1d8b1ea789e06d442522c8a1b2eebba0863c0de28f1c342483cc2270ff8f04f5f6e861b5802856b7289c796090a4a93836256e4b3e04bafe084d06f53d5f3f1fc510c52b92c201897264cdb2bc59a3a153842064c5ccd8aa056e81dc081ef5f455df4135c873b3c4f110c7ef1bd3544f6b3ef55dfc01487a75cc319
//private key (used to decrypt): 4c8da2628ce20e34994215d78f6568d58d9f130f8db9df2c10968a37565c10c0bd45dba2e06bfc54d68cb3dde942ec07551e79d8738fa6b881833ef83ed9e4902ddc48e8f9470d3aa1356b4a4cf426ec3b250bf1c0535c76f10dd1c21e9d533928cf575cd16c66f4420ce074664f2b052cae54722977b9829074f9103ca37af046a1b6e65e2008186776f136db63647b4cb77ebd826696519012bcad8b097493f58fe88b65de795d67806fc957eb51156a326f97789c0f22129edcbe801c210359c7b8b5ee38d10f1134a1a98969323d233c7a2b085488903f51f071a90aec8adf283bba0b79010a654663368e022acccdf6887f59cdb97100803225162ca27d
//Encrypted password: 492d4d9eb4d6a6939387f93b0367f151ffaf94631dd8a8244ee8fb500546bd13077957f7851e28d3c2bc8a5660fe5875a33086ec26f24d9bc678b4d9c0ab06983da2515280b05ffc98ed5b338921d1804369d010b3dc772cba5dcf3483fc0f260f02a1ccc67b4dc09c5e03b7ec9686c036a7d1b43256aa41650618c0c832b075bb3e4097622e1601ee09c58bb0bf88a5ea94868d2403b4db709e611072ee73d43b42972e6c310154aa2e595cbd9bbd183c14443cc16121ffe886f53321a284cae49a3bd1e74c4a55f20c0bc74e1882c140da328c67d560d7f926261a45686365d81b46eb776b3e43315c26dcccff7f7f880f09cb933817f4ddf16d4f71d75fa5

	public static String encryptPassword(String password, String publicKey_16encoded) {
		RSA rsa = new RSA();
		rsa.keys.e = BigInteger.valueOf(65537L);
		rsa.keys.n = new BigInteger(publicKey_16encoded, 16);
		BigInteger pwEncryped = rsa.encrypt(password);
		return pwEncryped.toString(16);
	}
	
	private static String decryptPassword(String encoded_passwd, String pubKey, String privKey) {
		RSA rsa = new RSA();
		rsa.keys.e = BigInteger.valueOf(65537L);
		rsa.keys.n = new BigInteger(pubKey, 16);
		rsa.keys.d = new BigInteger(privKey, 16);
		BigInteger passwd = new BigInteger(encoded_passwd, 16);
		String pwDecryped = rsa.decrypt(passwd);
		return pwDecryped;
	}

	/**
	 * Generate Password keys with 2048 bits
	 * @param args
	 */
	public static void main(String[] args) {
		if (false) {
			RSA rsa = new RSA();
			rsa.generateKeys(2048);
			System.out.println("public key  (used to encrypt): " + rsa.keys.n.toString(16));
			System.out.println("private key (used to decrypt): " + rsa.keys.d.toString(16));
		}
		
		String encoded = encryptPassword("Hamburg$!42", "d262c5e4931ecf89bc8148aefed71cca888928b419bc925c993247f78104cf7f285693df89a4ddf7c3d067afabac89a5f1dedc4056ff959868a4a382fa211f4b29378ffb62cba0fdacd8aec3b41b9100ce4ca90b229c763d5b4f6a911403d767b0d2c0de5a988cc408a4a911f2519f5dc4962cba4bc9e254ce94d38996af83b1251aeda1e1d8b1ea789e06d442522c8a1b2eebba0863c0de28f1c342483cc2270ff8f04f5f6e861b5802856b7289c796090a4a93836256e4b3e04bafe084d06f53d5f3f1fc510c52b92c201897264cdb2bc59a3a153842064c5ccd8aa056e81dc081ef5f455df4135c873b3c4f110c7ef1bd3544f6b3ef55dfc01487a75cc319");
		System.out.println("Encrypted password: " + encoded);

		String passw = decryptPassword(encoded,
				                       "d262c5e4931ecf89bc8148aefed71cca888928b419bc925c993247f78104cf7f285693df89a4ddf7c3d067afabac89a5f1dedc4056ff959868a4a382fa211f4b29378ffb62cba0fdacd8aec3b41b9100ce4ca90b229c763d5b4f6a911403d767b0d2c0de5a988cc408a4a911f2519f5dc4962cba4bc9e254ce94d38996af83b1251aeda1e1d8b1ea789e06d442522c8a1b2eebba0863c0de28f1c342483cc2270ff8f04f5f6e861b5802856b7289c796090a4a93836256e4b3e04bafe084d06f53d5f3f1fc510c52b92c201897264cdb2bc59a3a153842064c5ccd8aa056e81dc081ef5f455df4135c873b3c4f110c7ef1bd3544f6b3ef55dfc01487a75cc319",
				                       "4c8da2628ce20e34994215d78f6568d58d9f130f8db9df2c10968a37565c10c0bd45dba2e06bfc54d68cb3dde942ec07551e79d8738fa6b881833ef83ed9e4902ddc48e8f9470d3aa1356b4a4cf426ec3b250bf1c0535c76f10dd1c21e9d533928cf575cd16c66f4420ce074664f2b052cae54722977b9829074f9103ca37af046a1b6e65e2008186776f136db63647b4cb77ebd826696519012bcad8b097493f58fe88b65de795d67806fc957eb51156a326f97789c0f22129edcbe801c210359c7b8b5ee38d10f1134a1a98969323d233c7a2b085488903f51f071a90aec8adf283bba0b79010a654663368e022acccdf6887f59cdb97100803225162ca27d");
		System.out.println("Decrypted password: " + passw);
	}

}
