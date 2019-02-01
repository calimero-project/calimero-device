/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2019 B. Malinowsky

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Linking this library statically or dynamically with other modules is
    making a combined work based on this library. Thus, the terms and
    conditions of the GNU General Public License cover the whole
    combination.

    As a special exception, the copyright holders of this library give you
    permission to link this library with independent modules to produce an
    executable, regardless of the license terms of these independent
    modules, and to copy and distribute the resulting executable under terms
    of your choice, provided that you also meet, for each linked independent
    module, the terms and conditions of the license of that module. An
    independent module is a module which is not derived from or based on
    this library. If you modify this library, you may extend this exception
    to your version of the library, but you are not obligated to do so. If
    you do not wish to do so, delete this exception statement from your
    version.
*/

package tuwien.auto.calimero.device;

import static java.util.function.Predicate.isEqual;
import static java.util.function.Predicate.not;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.stream.IntStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.knxnetip.KnxSecureException;
import tuwien.auto.calimero.xml.KNXMLException;
import tuwien.auto.calimero.xml.XmlInputFactory;
import tuwien.auto.calimero.xml.XmlReader;

/**
 * Loads an ETS project keyring file. Not thread-safe.
 */
public final class Keyring {

	private static final String keyringNamespace = "http://knx.org/xml/keyring/1";
	private static final byte[] keyringSalt = utf8Bytes("1.keyring.ets.knx.org");

	private static final Logger logger = LoggerFactory.getLogger("calimero.device");

	private final String keyringUri;
	private final char[] keyringPassword;

	private byte[] passwordHash = {};
	private byte[] createdHash = {};

	private final Map<Object, Object> config = new HashMap<>();

	public Keyring(final String keyringUri, final char[] keyringPassword) {
		if (!keyringUri.endsWith(".knxkeys"))
			throw new KNXIllegalArgumentException("'" + keyringUri + "' is not a keyring file");

		this.keyringUri = keyringUri;
		this.keyringPassword = keyringPassword;
	}

	public void load() {
		try (var reader = XmlInputFactory.newInstance().createXMLReader(keyringUri)) {
			// call nextTag() to dive straight into first element, so we can check the keyring namespace
			reader.nextTag();

			final var namespace = reader.getNamespaceURI();
			if (!keyringNamespace.equals(namespace))
				throw new KNXMLException("keyring '" + keyringUri + "' with unsupported namespace '" + namespace + "'");

			if (!"Keyring".equals(reader.getLocalName()))
				throw new KNXMLException("keyring '" + keyringUri + "' requires 'Keyring' element");

			final var project = reader.getAttributeValue(null, "Project");
			final var createdBy = reader.getAttributeValue(null, "CreatedBy");
			final var created = reader.getAttributeValue(null, "Created");
			logger.debug("read keyring for project '{}', created by {} on {}", project, createdBy, created);

			passwordHash = pbkdf2WithHmacSha256(keyringPassword, keyringSalt);
			createdHash = sha256(utf8Bytes(created));

			final boolean strictVerification = true;
			verifySignature(reader.getAttributeValue(null, "Signature"), strictVerification);

			boolean inInterface = false;
			boolean inDevices = false;
			boolean inGroupAddresses = false;
			for (reader.next(); reader.getEventType() != XmlReader.END_DOCUMENT; reader.next()) {
				if (reader.getEventType() != XmlReader.START_ELEMENT)
					continue;

				final var name = reader.getLocalName();
				if ("Backbone".equals(name)) {
					final var mcastGroup = reader.getAttributeValue(null, "MulticastAddress");
					final var groupKey = decrypt(reader.getAttributeValue(null, "Key"));
					final var latency = Duration.ofMillis(Integer.parseInt(reader.getAttributeValue(null, "Latency")));

					config.put(mcastGroup, groupKey);
					config.put("latencyTolerance", latency);
				}
				else if ("Interface".equals(name)) { // [0, *]
					inInterface = true;
					inGroupAddresses = false;

					final var type = reader.getAttributeValue(null, "Type"); // { Backbone, Tunneling, USB }
					// rest is optional
					final var host = reader.getAttributeValue(null, "Host");
					final var addr = reader.getAttributeValue(null, "IndividualAddress");
					final var userId = reader.getAttributeValue(null, "UserID");
					final var pwd = reader.getAttributeValue(null, "Password");
					final var auth = reader.getAttributeValue(null, "Authentication");

					logger.trace("{} interface: {} {}, user {}, pwd {}, auth {}", type, host, addr, userId, pwd, auth);
				}
				else if (inInterface && "Group".equals(name)) { // [0, *]
					final var addr = new GroupAddress(reader.getAttributeValue(null, "Address"));
					final var senderList = reader.getAttributeValue(null, "Senders"); // list of addresses

					final var senders = new HashSet<IndividualAddress>();
					for (final String sender : senderList.split("\\s+", 0))
						senders.add(new IndividualAddress(sender));

					logger.trace("group {} senders = {}", addr, senders);
				}
				else if ("Devices".equals(name)) {
					inDevices = true;
				}
				else if (inDevices && "Device".equals(name)) { // [0, *]
					final var addr = new IndividualAddress(reader.getAttributeValue(null, "IndividualAddress"));
					// rest is optional
					final var toolkey = decrypt(reader.getAttributeValue(null, "ToolKey"));
					final var seq = reader.getAttributeValue(null, "SequenceNumber");
					final var pwd = reader.getAttributeValue(null, "ManagementPassword");
					final var auth = reader.getAttributeValue(null, "Authentication");

					logger.trace("device {} seq {}, toolkey {}, mgmt pwd {}, auth {}", addr, seq, safeKeyPrefix(toolkey), pwd, auth);
				}
				else if ("GroupAddresses".equals(name)) {
					inGroupAddresses = true;
					inInterface = false;
				}
				else if (inGroupAddresses && "Group".equals(name)) { // [0, *]
					final var addr = new GroupAddress(reader.getAttributeValue(null, "Address"));
					final var key = decrypt(reader.getAttributeValue(null, "Key"));

					config.put(addr, key);
				}
				else
					logger.warn("keyring '" + keyringUri + "': skip unknown element '{}'", name);
			}
		}
		catch (final KNXFormatException e) {
			throw new KNXMLException("loading keyring '" + keyringUri + "' address element with " + e.getMessage());
		}
		catch (final GeneralSecurityException e) {
			// NoSuchAlgorithmException, InvalidKeySpecException etc. imply a setup/programming error
			throw new KnxSecureException("crypto error", e);
		}
		finally {
			Arrays.fill(passwordHash, (byte) 0);
			Arrays.fill(createdHash, (byte) 0);
		}
	}

	public Map<?, ?> configuration() {
		return Collections.unmodifiableMap(config);
	}

	private byte[] decrypt(final String key) throws GeneralSecurityException {
		final byte[] decodedGroupKey = Base64.getDecoder().decode(key);
		return aes128Cbc(decodedGroupKey, passwordHash, createdHash);
	}

	private void verifySignature(final String signature, final boolean throwOnFailure) throws GeneralSecurityException {
		final var output = new ByteArrayOutputStream();
		try (var reader = XmlInputFactory.newInstance().createXMLReader(keyringUri)) {
			while (reader.next() != XmlReader.END_DOCUMENT) {
				if (reader.getEventType() == XmlReader.START_ELEMENT)
					appendElement(reader, output);
				else if (reader.getEventType() == XmlReader.END_ELEMENT)
					output.write(2);
			}
		}

		appendString(Base64.getEncoder().encode(passwordHash), output);

		final byte[] outputHash = sha256(output.toByteArray());
		final byte[] decoded = Base64.getDecoder().decode(signature);
		if (!Arrays.equals(outputHash, decoded)) {
			final String msg = "signature verification failed for keyring '" + keyringUri + "'";
			if (throwOnFailure)
				throw new KnxSecureException(msg);
			logger.warn(msg);
		}
	}

	private static void appendElement(final XmlReader reader, final ByteArrayOutputStream output) {
		output.write(1);
		appendString(utf8Bytes(reader.getLocalName()), output);

		IntStream.range(0, reader.getAttributeCount()).mapToObj(reader::getAttributeLocalName)
				.filter(not(isEqual("xmlns").or(isEqual("Signature")))).sorted()
				.forEach(attr -> appendAttribute(attr, reader, output));
	}

	private static void appendAttribute(final String attr, final XmlReader reader, final ByteArrayOutputStream output) {
		appendString(utf8Bytes(attr), output);
		appendString(utf8Bytes(reader.getAttributeValue(null, attr)), output);
	}

	private static void appendString(final byte[] str, final ByteArrayOutputStream output) {
		output.write(str.length);
		output.write(str, 0, str.length);
	}

	// TODO PKCS #7, device auth code, tunneling pwd
	private static byte[] extractPassword(final byte[] data) {
		final int b = data[31] & 0xff;
		final byte[] range = Arrays.copyOfRange(data, 8, 24 - b);
		return range;
	}

	private static byte[] aes128Cbc(final byte[] input, final byte[] key, final byte[] iv)
		throws GeneralSecurityException {

		final var cipher = Cipher.getInstance("AES/CBC/NoPadding");
		final var keySpec = new SecretKeySpec(key, "AES");
		final var params = new IvParameterSpec(iv);

		cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
		return cipher.doFinal(input);
	}

	private static byte[] sha256(final byte[] input) throws NoSuchAlgorithmException, DigestException {
		final var digest = MessageDigest.getInstance("SHA-256");
		digest.update(input);
		return Arrays.copyOf(digest.digest(), 16);
	}

	private static byte[] pbkdf2WithHmacSha256(final char[] password, final byte[] salt)
		throws GeneralSecurityException {
		final int iterations = 65_536;
		final int keyLength = 16 * 8;
		final var keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
		try {
			final var secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			logger.trace("using secret key provider {}", secretKeyFactory.getProvider());
			final var secretKey = secretKeyFactory.generateSecret(keySpec);
			return secretKey.getEncoded();
		}
		finally {
			keySpec.clearPassword();
		}
	}

	private static String safeKeyPrefix(final byte[] key) {
		return String.format("%x%x%x***", key[0], key[1], key[2]);
	}

	private static byte[] utf8Bytes(final String s) {
		return s.getBytes(StandardCharsets.UTF_8);
	}
}
