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
package oughttoprevail.prevailprotocol.keys;

import oughttoprevail.prevailprotocol.asymmetriccryptography.AsymmetricCryptography;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.FieldInputStream;
import oughttoprevail.prevailprotocol.storage.fields.FieldOutputStream;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;
import oughttoprevail.prevailprotocol.uid.UID;
import oughttoprevail.prevailprotocol.uid.UIDFactory;

/**
 * A {@link DataBundle} contains all keys generated at the start by a {@link oughttoprevail.prevailprotocol.User}, both public and private.
 */
public class DataBundle
{
	public static final SerDes<DataBundle> SER_DES = new SerDes<DataBundle>()
	{
		@Override
		public void serialize(DataBundle dataBundle, FieldOutputStream out, Settings settings)
		{
			out.writeObject(dataBundle.getIdentityKeys(), IdentifiableKeyPair.SER_DES);
			out.writeObject(dataBundle.getSignedPreKey(), SignedPreKey.SER_DES);
			IdentifiableKeyPair[] oneTimePreKeys = dataBundle.getOneTimePreKeys();
			for(IdentifiableKeyPair oneTimePreKey : oneTimePreKeys)
			{
				out.writeObject(oneTimePreKey, IdentifiableKeyPair.SER_DES);
			}
		}
		
		@Override
		public DataBundle deserialize(FieldInputStream in, Settings settings)
		{
			IdentifiableKeyPair identityKeys = in.readObject(IdentifiableKeyPair.SER_DES);
			SignedPreKey signedPreKey = in.readObject(SignedPreKey.SER_DES);
			int defaultTotalOneTimePreKeys = settings.getDefaultTotalOneTimePreKeys();
			IdentifiableKeyPair[] oneTimePreKeys = new IdentifiableKeyPair[defaultTotalOneTimePreKeys];
			for(int i = 0; i < defaultTotalOneTimePreKeys; i++)
			{
				oneTimePreKeys[i] = in.readObject(IdentifiableKeyPair.SER_DES);
			}
			return new DataBundle(identityKeys, signedPreKey, oneTimePreKeys);
		}
	};
	
	private final IdentifiableKeyPair identityKeys;
	private final SignedPreKey signedPreKey;
	private final IdentifiableKeyPair[] oneTimePreKeys;
	
	private DataBundle(IdentifiableKeyPair identityKeys, SignedPreKey signedPreKey, IdentifiableKeyPair[] oneTimePreKeys)
	{
		this.identityKeys = identityKeys;
		this.signedPreKey = signedPreKey;
		this.oneTimePreKeys = oneTimePreKeys;
	}
	
	public IdentifiableKeyPair getIdentityKeys()
	{
		return identityKeys;
	}
	
	public SignedPreKey getSignedPreKey()
	{
		return signedPreKey;
	}
	
	public IdentifiableKeyPair[] getOneTimePreKeys()
	{
		return oneTimePreKeys;
	}
	
	/**
	 * @param settings to use
	 * @return a new random {@link DataBundle} based on the specified settings
	 */
	public static DataBundle newBundle(Settings settings)
	{
		UIDFactory uidFactory = settings.getUIDFactory();
		AsymmetricCryptography asymmetricCryptography = settings.getAsymmetricCryptography();
		KeyPair identityKeys = asymmetricCryptography.generateKeyPair();
		UID identityKeysUID = uidFactory.generateUID();
		int defaultTotalOneTimePreKeys = settings.getDefaultTotalOneTimePreKeys();
		IdentifiableKeyPair[] oneTimePreKeyPairs = new IdentifiableKeyPair[defaultTotalOneTimePreKeys];
		for(int i = 0; i < defaultTotalOneTimePreKeys; i++)
		{
			oneTimePreKeyPairs[i] = new IdentifiableKeyPair(uidFactory.generateUID(), asymmetricCryptography.generateKeyPair());
		}
		return new DataBundle(new IdentifiableKeyPair(identityKeysUID, identityKeys),
				generateSignedPreKey(identityKeys, settings),
				oneTimePreKeyPairs);
	}
	
	/**
	 * @param identityKeys to sign the public signed pre key with
	 * @param settings to use
	 * @return a random signed pre key based on the specified settings
	 */
	public static SignedPreKey generateSignedPreKey(KeyPair identityKeys, Settings settings)
	{
		AsymmetricCryptography asymmetricCryptography = settings.getAsymmetricCryptography();
		KeyPair signedPreKeys = asymmetricCryptography.generateKeyPair();
		UID signedPreKeysUID = settings.getUIDFactory().generateUID();
		byte[] preKeySignature = asymmetricCryptography.sign(signedPreKeys.getPublicKey(), identityKeys.getPrivateKey());
		return new SignedPreKey(signedPreKeysUID, signedPreKeys, preKeySignature, System.currentTimeMillis() + settings.getSignedPreKeyKeepAlive());
	}
}