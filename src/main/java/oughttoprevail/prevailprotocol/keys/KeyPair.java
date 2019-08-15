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

/**
 * A {@link KeyPair} is a container for both a private and public keys.
 */
public class KeyPair
{
	public static final SerDes<KeyPair> SER_DES = new SerDes<KeyPair>()
	{
		@Override
		public void serialize(KeyPair keyPair, FieldOutputStream out, Settings settings)
		{
			out.writeBytes(keyPair.getPrivateKey());
			out.writeBytes(keyPair.getPublicKey());
		}
		
		@Override
		public KeyPair deserialize(FieldInputStream in, Settings settings)
		{
			return new KeyPair(in.readBytes(), in.readBytes());
		}
	};
	
	private final byte[] privateKey;
	private final byte[] publicKey;
	
	public KeyPair(byte[] privateKey, byte[] publicKey)
	{
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}
	
	public byte[] getPrivateKey()
	{
		return privateKey;
	}
	
	public byte[] getPublicKey()
	{
		return publicKey;
	}
}