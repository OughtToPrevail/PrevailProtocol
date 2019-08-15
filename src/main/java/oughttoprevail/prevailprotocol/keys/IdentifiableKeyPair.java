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

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.FieldInputStream;
import oughttoprevail.prevailprotocol.storage.fields.FieldOutputStream;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;
import oughttoprevail.prevailprotocol.uid.UID;

/**
 * An {@link IdentifiableKey} is a {@link KeyPair} with an associated {@link UID} identifier.
 */
public class IdentifiableKeyPair extends KeyPair
{
	public static final SerDes<IdentifiableKeyPair> SER_DES = new SerDes<IdentifiableKeyPair>()
	{
		@Override
		public void serialize(IdentifiableKeyPair identifiableKeyPair, FieldOutputStream out, Settings settings)
		{
			out.writeObject(identifiableKeyPair.getUID(), settings.getUIDFactory());
			out.writeObject(identifiableKeyPair, KeyPair.SER_DES);
		}
		
		@Override
		public IdentifiableKeyPair deserialize(FieldInputStream in, Settings settings)
		{
			return new IdentifiableKeyPair(in.readObject(settings.getUIDFactory()), in.readObject(KeyPair.SER_DES));
		}
	};
	
	/**
	 * Identifier of the key pair
	 */
	private final UID uid;
	
	IdentifiableKeyPair(UID uid, KeyPair keyPair)
	{
		this(uid, keyPair.getPrivateKey(), keyPair.getPublicKey());
	}
	
	private IdentifiableKeyPair(UID uid, byte[] privateKey, byte[] publicKey)
	{
		super(privateKey, publicKey);
		this.uid = uid;
	}
	
	/**
	 * @return the key pair identifier
	 */
	public UID getUID()
	{
		return uid;
	}
}