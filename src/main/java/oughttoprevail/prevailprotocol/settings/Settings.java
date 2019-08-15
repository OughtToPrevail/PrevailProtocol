/*
PrevailProtocol.
Copyright (C) 2019  https://github.com/OughtToPrevail

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package oughttoprevail.prevailprotocol.settings;

import java.io.File;
import java.nio.charset.Charset;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import oughttoprevail.prevailprotocol.asymmetriccryptography.AsymmetricCryptography;
import oughttoprevail.prevailprotocol.asymmetriccryptography.X25519;
import oughttoprevail.prevailprotocol.kdf.HKDFFactory;
import oughttoprevail.prevailprotocol.kdf.KDFFactory;
import oughttoprevail.prevailprotocol.random.RandomBytesGenerator;
import oughttoprevail.prevailprotocol.random.SecureRandomBytesGenerator;
import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.storage.files.FiledDirectory;
import oughttoprevail.prevailprotocol.uid.StringWrapperFactory;
import oughttoprevail.prevailprotocol.uid.TimedUIDFactory;
import oughttoprevail.prevailprotocol.uid.UIDFactory;

/**
 * {@link Settings} provides a way to control the behavior of a {@link oughttoprevail.prevailprotocol.User}.
 */
public class Settings
{
	/**
	 * The default settings, when a custom {@link Settings} is not provided this will be the default
	 */
	private static final Settings DEFAULT_SETTINGS;
	
	static
	{
		//create a new charset encase this is Android which doesn't have StandardCharsets.UTF_8
		Charset stringCharset = Charset.forName("UTF-8");
		FiledDirectory filedDirectory = new FiledDirectory(System.getProperty("user.home") + File.separatorChar + "PrevailProtocolData",
				256,
				Throwable::printStackTrace);
		DEFAULT_SETTINGS = new Settings().asymmetricCryptography(new X25519())
										 .random(new SecureRandomBytesGenerator())
										 .kdfFactory(new HKDFFactory())
										 .initialDirectory(filedDirectory)
										 .uidFactory(new TimedUIDFactory())
										 .userIdFactory(new StringWrapperFactory(stringCharset))
										 .scheduler(Executors.newSingleThreadScheduledExecutor(runnable ->
										 {
											 Thread thread = new Thread(runnable, "DefaultSettings - Scheduler");
											 thread.setDaemon(true);
											 return thread;
										 }))
										 .provider(null)
										 .macAlgorithm("HMacSHA256")
										 .symmetricAlgorithm("AES")
										 .cipherAlgorithm("AES/CBC/PKCS5Padding")
										 .fingerprintDigestAlgorithm("SHA-256")
										 .useHeaderEncryption(false)
										 .useUpdateAAD(false)
										 .symmetricKeySize(32)
										 .outputHashSize(32)
										 .ivSize(16)
										 .macKeySize(32)
										 .messageMacSize(16)
										 .nonceSize(32)
										 .defaultTotalOneTimePreKeys(100)
										 .maxSkipKeys(100)
										 .maxStoredSkippedKeys(500)
										 .maxDevices(2)
										 .signedPreKeyKeepAlive(TimeUnit.DAYS.toMillis(2))
										 .skippedKeyKeepAlive(TimeUnit.DAYS.toMillis(1))
										 .groupSessionDeletionKeepAlive(TimeUnit.DAYS.toMillis(1))
										 .dhRatchetInfo("DHRatchet".getBytes(stringCharset))
										 .symmetricRatchetInfo("SymmetricRatchet".getBytes(stringCharset))
										 .headerKeyInfo("HeaderKey".getBytes(stringCharset))
										 .messageKeySeed(new byte[]{1})
										 .chainKeySeed(new byte[]{2});
		filedDirectory.initSettings(DEFAULT_SETTINGS);
	}
	
	public static Settings getDefaultSettings()
	{
		return DEFAULT_SETTINGS;
	}
	
	//objects
	/**
	 * Authentication, key generation and key exchange
	 */
	private AsymmetricCryptography asymmetricCryptography;
	/**
	 * Random bytes generator
	 */
	private RandomBytesGenerator random;
	/**
	 * KDF factory for creating {@link oughttoprevail.prevailprotocol.kdf.KDF}
	 */
	private KDFFactory kdfFactory;
	/**
	 * The initial directory which creates all other directories and possibly storages.
	 */
	private Directory initialDirectory;
	/**
	 * {@link UIDFactory} which is used for keys, and device ids
	 */
	private UIDFactory uidFactory;
	/**
	 * {@link UIDFactory} which is used for only the user identifier
	 */
	private UIDFactory userIdFactory;
	/**
	 * Task schedueler
	 */
	private ScheduledExecutorService scheduler;
	
	/**
	 * The java security provider or {@code null} if all providers available providers should be used
	 */
	private Provider provider;
	
	//algorithms
	/**
	 * Algorithm for {@link javax.crypto.Mac} (examples: "HMacSHA256", "HMacSHA512")
	 */
	private String macAlgorithm;
	/**
	 * Symmetric algorithm (examples: "AES", "DES")
	 */
	private String symmetricAlgorithm;
	/**
	 * Algorithm for {@link javax.crypto.Cipher} (examples: "AES/CBC/PKCS5Padding" "AES/GCM/PKCS5Padding")
	 */
	private String cipherAlgorithm;
	/**
	 * Algorithm for {@link java.security.MessageDigest} (examples: "SHA-256", "SHA-512")
	 */
	private String fingerprintDigestAlgorithm;
	
	//binary options
	/**
	 * Whether to use header encryption
	 *
	 * @see <a href="https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption">What is "Header Encryption"</a>
	 */
	private boolean useHeaderEncryption;
	/**
	 * Whether to use {@link javax.crypto.Cipher#updateAAD(byte[])} instead of a encrypt-then-mac
	 */
	private boolean useUpdateAAD;
	
	//sizes
	/**
	 * {@link javax.crypto.Cipher} key size in bytes
	 */
	private int symmetricKeySize;
	/**
	 * Output hash size of {@link javax.crypto.Mac} with the specified {@link #macAlgorithm} in bytes
	 */
	private int outputHashSize;
	/**
	 * Initialization vector size in bytes
	 */
	private int ivSize;
	/**
	 * {@link javax.crypto.Mac} key size in bytes
	 */
	private int macKeySize;
	/**
	 * Message mac size in bytes
	 */
	private int messageMacSize;
	/**
	 * Nonce size in bytes
	 */
	private int nonceSize;
	
	/**
	 * Default total amount of one time pre keys.
	 * This basically means the amount of one time pre keys to be generated when the data bundle is first generating.
	 */
	private int defaultTotalOneTimePreKeys;
	
	//max
	/**
	 * Max amount of keys to skip at once
	 */
	private int maxSkipKeys;
	/**
	 * Max amount of skipped keys to be skipped per session if {@link oughttoprevail.prevailprotocol.session.Session} or per group if using
	 * {@link oughttoprevail.prevailprotocol.group.Group}
	 */
	private int maxStoredSkippedKeys;
	/**
	 * Max amount of devices per user
	 */
	private int maxDevices;
	
	//keep alive - when to delete
	/**
	 * How long should a signed pre key stay, once this time has ran out a new signed pre key is generated and the old one is deleted
	 */
	private long signedPreKeyKeepAlive;
	/**
	 * How long should a skipped key stay, once this time has ran out the skipped key is deleted
	 */
	private long skippedKeyKeepAlive;
	/**
	 * How long should a group session stay after it has been requested to be deleted, once this time has ran out the session will be deleted
	 */
	private long groupSessionDeletionKeepAlive;
	
	//info
	/**
	 * Information for {@link oughttoprevail.prevailprotocol.doubleratchet.DHRatchet}
	 */
	private byte[] dhRatchetInfo;
	/**
	 * Information for {@link oughttoprevail.prevailprotocol.doubleratchet.SymmetricKeyRatchet}
	 */
	private byte[] symmetricRatchetInfo;
	/**
	 * Information for header keys
	 */
	private byte[] headerKeyInfo;
	
	//KDF seeds
	/**
	 * Message key KDF seed
	 */
	private byte[] messageKeySeed;
	/**
	 * Chain key KDF seed
	 */
	private byte[] chainKeySeed;
	
	/**
	 * @return a new {@link Settings} with the default values
	 */
	public static Settings create()
	{
		return create(DEFAULT_SETTINGS);
	}
	
	/**
	 * @param parent of the new {@link Settings}
	 * @return a new {@link Settings} with all the values of the specified parent
	 */
	public static Settings create(Settings parent)
	{
		return new Settings(parent);
	}
	
	/**
	 * Constructs a new {@link Settings} with all the variables being empty.
	 * <b>NOTE: using this is not recommended and will most likely result in lots of exceptions unless all variables are set before this
	 * {@link Settings is used</b>
	 */
	public Settings()
	{
	
	}
	
	/**
	 * Constructs a new {@link Settings} with all the variables values matching the ones specified in the specified parent.
	 *
	 * @param parent of the new {@link Settings}
	 */
	public Settings(Settings parent)
	{
		asymmetricCryptography(parent.getAsymmetricCryptography()).random(parent.getRandom())
																  .kdfFactory(parent.getKDFFactory())
																  .initialDirectory(parent.getInitialDirectory())
																  .uidFactory(parent.getUIDFactory())
																  .userIdFactory(parent.getUserIdFactory())
																  .scheduler(parent.getScheduler())
																  .macAlgorithm(parent.getMacAlgorithm())
																  .symmetricAlgorithm(parent.getSymmetricAlgorithm())
																  .cipherAlgorithm(parent.getCipherAlgorithm())
																  .fingerprintDigestAlgorithm(parent.getFingerprintDigestAlgorithm())
																  .useHeaderEncryption(parent.isUseHeaderEncryption())
																  .useUpdateAAD(parent.isUseUpdateAAD())
																  .symmetricKeySize(parent.getSymmetricKeySize())
																  .outputHashSize(parent.getOutputHashSize())
																  .ivSize(parent.getIVSize())
																  .macKeySize(parent.getMacKeySize())
																  .messageMacSize(parent.getMessageMacSize())
																  .nonceSize(parent.getNonceSize())
																  .defaultTotalOneTimePreKeys(parent.getDefaultTotalOneTimePreKeys())
																  .maxSkipKeys(parent.getMaxSkipKeys())
																  .maxStoredSkippedKeys(parent.getMaxStoredSkippedKeys())
																  .maxDevices(parent.getMaxDevices())
																  .signedPreKeyKeepAlive(parent.getSignedPreKeyKeepAlive())
																  .skippedKeyKeepAlive(parent.getSkippedKeyKeepAlive())
																  .groupSessionDeletionKeepAlive(parent.getGroupSessionDeletionKeepAlive())
																  .dhRatchetInfo(parent.getDHRatchetInfo())
																  .symmetricRatchetInfo(parent.getSymmetricRatchetInfo())
																  .headerKeyInfo(parent.getHeaderKeyInfo())
																  .messageKeySeed(parent.getMessageKeySeed())
																  .chainKeySeed(parent.getChainKeySeed());
		this.provider = parent.getProvider();
	}
	
	public Settings asymmetricCryptography(AsymmetricCryptography asymmetricCryptography)
	{
		this.asymmetricCryptography = asymmetricCryptography;
		return this;
	}
	
	public Settings random(RandomBytesGenerator random)
	{
		this.random = random;
		return this;
	}
	
	public Settings kdfFactory(KDFFactory kdfFactory)
	{
		this.kdfFactory = kdfFactory;
		return this;
	}
	
	public Settings initialDirectory(Directory initialDirectory)
	{
		this.initialDirectory = initialDirectory;
		return this;
	}
	
	public Settings uidFactory(UIDFactory uidFactory)
	{
		this.uidFactory = uidFactory;
		return this;
	}
	
	public Settings userIdFactory(UIDFactory userIdFactory)
	{
		this.userIdFactory = userIdFactory;
		return this;
	}
	
	public Settings scheduler(ScheduledExecutorService scheduler)
	{
		this.scheduler = scheduler;
		return this;
	}
	
	public Settings provider(String provider)
	{
		if(provider == null)
		{
			this.provider = null;
		} else
		{
			Provider providerObject = Security.getProvider(provider);
			if(providerObject == null)
			{
				throw new IllegalArgumentException("Specified provider doesn't exist!");
			}
			this.provider = providerObject;
		}
		return this;
	}
	
	public Settings macAlgorithm(String macAlgorithm)
	{
		this.macAlgorithm = macAlgorithm;
		return this;
	}
	
	public Settings symmetricAlgorithm(String symmetricAlgorithm)
	{
		this.symmetricAlgorithm = symmetricAlgorithm;
		return this;
	}
	
	public Settings cipherAlgorithm(String cipherAlgorithm)
	{
		this.cipherAlgorithm = cipherAlgorithm;
		return this;
	}
	
	public Settings fingerprintDigestAlgorithm(String fingerprintDigestAlgorithm)
	{
		this.fingerprintDigestAlgorithm = fingerprintDigestAlgorithm;
		return this;
	}
	
	public Settings useHeaderEncryption(boolean useHeaderEncryption)
	{
		this.useHeaderEncryption = useHeaderEncryption;
		return this;
	}
	
	public Settings useUpdateAAD(boolean useUpdateAAD)
	{
		this.useUpdateAAD = useUpdateAAD;
		return this;
	}
	
	public Settings symmetricKeySize(int symmetricKeySize)
	{
		this.symmetricKeySize = symmetricKeySize;
		return this;
	}
	
	public Settings outputHashSize(int outputHashSize)
	{
		this.outputHashSize = outputHashSize;
		return this;
	}
	
	public Settings ivSize(int ivSize)
	{
		this.ivSize = ivSize;
		return this;
	}
	
	public Settings macKeySize(int macKeySize)
	{
		this.macKeySize = macKeySize;
		return this;
	}
	
	public Settings messageMacSize(int messageMacSize)
	{
		this.messageMacSize = messageMacSize;
		return this;
	}
	
	public Settings nonceSize(int nonceSize)
	{
		this.nonceSize = nonceSize;
		return this;
	}
	
	public Settings defaultTotalOneTimePreKeys(int defaultTotalOneTimePreKeys)
	{
		this.defaultTotalOneTimePreKeys = defaultTotalOneTimePreKeys;
		return this;
	}
	
	public Settings maxSkipKeys(int maxSkipKeys)
	{
		this.maxSkipKeys = maxSkipKeys;
		return this;
	}
	
	public Settings maxStoredSkippedKeys(int maxStoredSkippedKeys)
	{
		this.maxStoredSkippedKeys = maxStoredSkippedKeys;
		return this;
	}
	
	public Settings maxDevices(int maxDevices)
	{
		this.maxDevices = maxDevices;
		return this;
	}
	
	public Settings signedPreKeyKeepAlive(long signedPreKeyKeepAlive)
	{
		this.signedPreKeyKeepAlive = signedPreKeyKeepAlive;
		return this;
	}
	
	public Settings skippedKeyKeepAlive(long skippedKeyKeepAlive)
	{
		this.skippedKeyKeepAlive = skippedKeyKeepAlive;
		return this;
	}
	
	public Settings groupSessionDeletionKeepAlive(long groupSessionDeletionKeepAlive)
	{
		this.groupSessionDeletionKeepAlive = groupSessionDeletionKeepAlive;
		return this;
	}
	
	public Settings dhRatchetInfo(byte[] dhRatchetInfo)
	{
		this.dhRatchetInfo = dhRatchetInfo;
		return this;
	}
	
	public Settings symmetricRatchetInfo(byte[] symmetricRatchetInfo)
	{
		this.symmetricRatchetInfo = symmetricRatchetInfo;
		return this;
	}
	
	public Settings headerKeyInfo(byte[] headerKeyInfo)
	{
		this.headerKeyInfo = headerKeyInfo;
		return this;
	}
	
	public Settings messageKeySeed(byte[] messageKeySeed)
	{
		this.messageKeySeed = messageKeySeed;
		return this;
	}
	
	public Settings chainKeySeed(byte[] chainKeySeed)
	{
		this.chainKeySeed = chainKeySeed;
		return this;
	}
	
	public AsymmetricCryptography getAsymmetricCryptography()
	{
		return asymmetricCryptography;
	}
	
	public RandomBytesGenerator getRandom()
	{
		return random;
	}
	
	public KDFFactory getKDFFactory()
	{
		return kdfFactory;
	}
	
	public Directory getInitialDirectory()
	{
		return initialDirectory;
	}
	
	public UIDFactory getUIDFactory()
	{
		return uidFactory;
	}
	
	public UIDFactory getUserIdFactory()
	{
		return userIdFactory;
	}
	
	public ScheduledExecutorService getScheduler()
	{
		return scheduler;
	}
	
	public Provider getProvider()
	{
		return provider;
	}
	
	public String getMacAlgorithm()
	{
		return macAlgorithm;
	}
	
	public String getSymmetricAlgorithm()
	{
		return symmetricAlgorithm;
	}
	
	public String getCipherAlgorithm()
	{
		return cipherAlgorithm;
	}
	
	public String getFingerprintDigestAlgorithm()
	{
		return fingerprintDigestAlgorithm;
	}
	
	public boolean isUseHeaderEncryption()
	{
		return useHeaderEncryption;
	}
	
	public boolean isUseUpdateAAD()
	{
		return useUpdateAAD;
	}
	
	public int getSymmetricKeySize()
	{
		return symmetricKeySize;
	}
	
	public int getOutputHashSize()
	{
		return outputHashSize;
	}
	
	public int getIVSize()
	{
		return ivSize;
	}
	
	public int getMacKeySize()
	{
		return macKeySize;
	}
	
	public int getMessageMacSize()
	{
		return messageMacSize;
	}
	
	public int getNonceSize()
	{
		return nonceSize;
	}
	
	public int getDefaultTotalOneTimePreKeys()
	{
		return defaultTotalOneTimePreKeys;
	}
	
	public int getMaxSkipKeys()
	{
		return maxSkipKeys;
	}
	
	public int getMaxStoredSkippedKeys()
	{
		return maxStoredSkippedKeys;
	}
	
	public int getMaxDevices()
	{
		return maxDevices;
	}
	
	public long getSignedPreKeyKeepAlive()
	{
		return signedPreKeyKeepAlive;
	}
	
	public long getSkippedKeyKeepAlive()
	{
		return skippedKeyKeepAlive;
	}
	
	public long getGroupSessionDeletionKeepAlive()
	{
		return groupSessionDeletionKeepAlive;
	}
	
	public byte[] getDHRatchetInfo()
	{
		return dhRatchetInfo;
	}
	
	public byte[] getSymmetricRatchetInfo()
	{
		return symmetricRatchetInfo;
	}
	
	public byte[] getHeaderKeyInfo()
	{
		return headerKeyInfo;
	}
	
	public byte[] getMessageKeySeed()
	{
		return messageKeySeed;
	}
	
	public byte[] getChainKeySeed()
	{
		return chainKeySeed;
	}
}