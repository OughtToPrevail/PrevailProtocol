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
 * A {@link SignedPreKey} is a container for all information needed for a signed pre key.
 */
public class SignedPreKey extends IdentifiableKeyPair
{
	public static final SerDes<SignedPreKey> SER_DES = new SerDes<SignedPreKey>()
	{
		@Override
		public void serialize(SignedPreKey signedPreKey, FieldOutputStream out, Settings settings)
		{
			out.writeObject(signedPreKey, IdentifiableKeyPair.SER_DES);
			out.writeBytes(signedPreKey.getPreKeySignature());
			out.writeLong(signedPreKey.getExpirationTime());
		}
		
		@Override
		public SignedPreKey deserialize(FieldInputStream in, Settings settings)
		{
			return new SignedPreKey(in.readObject(IdentifiableKeyPair.SER_DES), in.readBytes(), in.readLong());
		}
	};
	
	/**
	 * Pre key signature signed with the user's identity key
	 */
	private final byte[] preKeySignature;
	/**
	 * When this signed pre key expires, when a signed pre key expires it should be replaced with a newer {@link SignedPreKey}
	 */
	private final long expirationTime;
	
	private SignedPreKey(IdentifiableKeyPair identifiableKeyPair, byte[] preKeySignature, long expirationTime)
	{
		this(identifiableKeyPair.getUID(), identifiableKeyPair, preKeySignature, expirationTime);
	}
	
	SignedPreKey(UID uid, KeyPair keyPair, byte[] preKeySignature, long expirationTime)
	{
		super(uid, keyPair);
		this.preKeySignature = preKeySignature;
		this.expirationTime = expirationTime;
	}
	
	public byte[] getPreKeySignature()
	{
		return preKeySignature;
	}
	
	public long getExpirationTime()
	{
		return expirationTime;
	}
}